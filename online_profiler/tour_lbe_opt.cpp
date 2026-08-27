/* **********************************************************
 * Copyright (c) 2026 National University of Singapore.  All rights reserved.
 * Copyright (c) 2014-2021 Google, Inc.  All rights reserved.
 * Copyright (c) 2008 VMware, Inc.  All rights reserved.
 * **********************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 * 
 * Author: Dongin Lee
 * 
 */

#include "dr_api.h"
#include "drmgr.h"
#include <cstdint>
#include <unordered_map>
#include <algorithm>

// Number of address bits used for indexing the "Outcome Frequency Table (OFT)"
#define ADDRESS_LENGTH 48
// Number of history bits used for indexing the OFT
#define HISTORY_LENGTH 20

// Mutex protecting accesses to the global OFT
static void *map_lock;

// Counts taken and not-taken outcomes for a branch under a given history
typedef struct _counter_per_branch_t {
    uint64_t n_taken;
    uint64_t n_not_taken;
} counter_per_branch_t;

// Stores the taken probability and linear branch entropy for a branch-history pair
typedef struct _entropy_info_t {
    double taken_probability;
    double linear_entropy;
} entropy_info_t;


/* ******* Data structures and variables for the global history ******* */

// Global branch history and mask used to retain the most recent branch outcomes
#define GLOBAL_PATTERN uint32_t
#define GLOBAL_HISTORY_MASK (( 1u << HISTORY_LENGTH ) - 1 )
GLOBAL_PATTERN global_pattern = 0;

// OFT indexed by branch address and global history
#define GLOBAL_OFT_DATA_STRUCTURE std::unordered_map<app_pc, std::unordered_map<GLOBAL_PATTERN, counter_per_branch_t>> 
GLOBAL_OFT_DATA_STRUCTURE global_oft;

// Stores the branch entropy of each branch based on global history
#define TOUR_PREDICTOR_GLOBAL std::unordered_map<app_pc, double>


/* ******* Data structures and variables for local history ******* */

// Local branch history and mask used to retain the most recent branch outcomes
#define LOCAL_PATTERN uint32_t
#define LOCAL_HISTORY_MASK ( ( 1u << HISTORY_LENGTH ) - 1 )

// Stores the local history pattern for each branch instruction
#define PER_BRANCH_PATTERN std::unordered_map<app_pc, LOCAL_PATTERN> 
PER_BRANCH_PATTERN pattern_per_branch;

// OFT indexed by branch address and local history
#define LOCAL_OFT_DATA_STRUCTURE std::unordered_map<app_pc, std::unordered_map<LOCAL_PATTERN, counter_per_branch_t>> 
LOCAL_OFT_DATA_STRUCTURE local_oft;

// Stores the branch entropy of each branch based on local history
#define TOUR_PREDICTOR_LOCAL std::unordered_map<app_pc, double>


/* ******* Data structures and variables for tournament branch entropy ******* */

// Stores the selected entropy for each branch address
#define TOUR_ENTROPY_OFT std::unordered_map<app_pc, double>
TOUR_ENTROPY_OFT tour_entropy_oft;

#define TOUR_ENTROPY_LIST std::unordered_map<int, double>
TOUR_ENTROPY_LIST tour_entropy_list;

#define TOUR_ENTROPY_LIST_ALIASING std::unordered_map< int, std::unordered_map<int, double> >
TOUR_ENTROPY_LIST_ALIASING tour_entropy_list_aliasing;


/*
 * Accumulators for global- and local-history entropy
 * for the current address and history lengths 
 */
double      tour_entropy_per_addr_global_aliasing       = 0;
double      tour_entropy_per_addr_local_aliasing        = 0;
uint64_t    total_instructions_per_addr_global_aliasing = 0;
uint64_t    total_instructions_per_addr_local_aliasing  = 0;
double      average_tour_entropy_per_bit                = 0;


static void
cbr_count(void *drcontext, app_pc src, app_pc targ, int taken)
{
    dr_mutex_lock(map_lock);

    /* Record the branch outcome for both global and local history */
    
    // Record the history preceding the current branch
    GLOBAL_PATTERN global_history = global_pattern;

    /*
     *  Record the branch outcome under the current global history,
     *  then update the history with the observed outcome
     */
    auto &taken_update_global = global_oft[src];
    if (taken)
    {
        taken_update_global[global_history].n_taken++;
        global_pattern = (  ( global_history << 1 ) | 1 ) & GLOBAL_HISTORY_MASK;
    }
    else
    {
        taken_update_global[global_history].n_not_taken++;
        global_pattern = (  ( global_history << 1 ) | 0 ) & GLOBAL_HISTORY_MASK;
    }


    // Record the history preceding the current branch
    LOCAL_PATTERN local_history = pattern_per_branch[src];

    /*
     *  Record the branch outcome under the current local history,
     *  then update the history with the observed outcome
     */
    auto &taken_update_local = local_oft[src];
    if (taken)
    {
        taken_update_local[local_history].n_taken++;        
        pattern_per_branch[src] = (  ( local_history << 1 ) | 1 ) & LOCAL_HISTORY_MASK;
    }
    else
    {
        taken_update_local[local_history].n_not_taken++;        
        pattern_per_branch[src] = (  ( local_history << 1 ) | 0 ) & LOCAL_HISTORY_MASK;
    }

    dr_mutex_unlock(map_lock);
}

static void
record_tour_entropy(TOUR_PREDICTOR_GLOBAL &global_entry, TOUR_PREDICTOR_LOCAL &local_entry, TOUR_ENTROPY_OFT &tour_entry)
{
    /*
     * Select the lower entropy between the global- and local-history
     * for each branch address
     */

    for (auto &g : global_entry) 
    {
        app_pc global_tour_addr = g.first;

        for (auto &l : local_entry)
        {
            if(g.first == l.first)
            {
                if(g.second >= l.second)
                {   tour_entry[global_tour_addr] = l.second;  }
                else
                {   tour_entry[global_tour_addr] = g.second;  }
            }
        }
    }
}


static void
average_tour_entropy_aliasing(TOUR_ENTROPY_OFT &entries, int address_length, int bit_length)
{
    average_tour_entropy_per_bit = 0;

    /*
     * Average the tournament entropy across all branch addresses
     * and store the result for the current address and history lengths
     */
    for (auto &t : entries)
    {
        average_tour_entropy_per_bit += t.second;
    }

    auto &aliasing_value = tour_entropy_list_aliasing[address_length];
    aliasing_value[bit_length] = average_tour_entropy_per_bit / double(entries.size());
    // dr_printf("************* entropy: %.6lf, # of entries: %u *************\n\n", aliasing_value[bit_length], entries.size());
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data)
{
    // Instrument conditional branch instructions
    if(!instr_is_cbr(instr))
        return DR_EMIT_DEFAULT;    
    dr_insert_cbr_instrumentation(drcontext, bb, instr, (void*)cbr_count);

    return DR_EMIT_DEFAULT;
}

void
dr_exit(void)
{
    /*
     * Compute branch entropy by applying the address- and history-merging
     * Optimizations described in the Linear Branch Entropy paper
     */

    /*
     * Outer loop progressively merges address bits
     * Inner loop progressively merges history bits
    */

    // ==== outer loop ====
    for(int address_length = ADDRESS_LENGTH; address_length >= 0; --address_length)
    {
        uint64_t address_merging_mask = ( (uint64_t) 1 << address_length) - 1;

        // ********** Global History Part **********
        /*
         * Declare a variable to temporarily record data by merging address bits
         * To efficiently use memory, the variable is declared inside block
         */
        {
            GLOBAL_OFT_DATA_STRUCTURE global_aliasing_pc_temp;

            for(auto &aliasing_entry : global_oft)
            {
                // Merge address bits and map branches to the new aliased address
                app_pc pc = aliasing_entry.first;
                uintptr_t new_address = ((uintptr_t) pc) & address_merging_mask;
                auto &aliasing_map = global_aliasing_pc_temp[app_pc(new_address)];
            
                // Merge branch outcome counts for branches mapped to the same aliased address
                auto &old_counter  = aliasing_entry.second;

                for (auto &temp : old_counter)
                {
                    auto &old_hist  = temp.first;
                    auto &old_count = temp.second;
                    auto &temp_hist = aliasing_map[old_hist];

                    temp_hist.n_taken += old_count.n_taken;
                    temp_hist.n_not_taken += old_count.n_not_taken;
                }
            }

            global_oft.swap(global_aliasing_pc_temp);
        }

        // ********** Local History Part **********
        /*
         * Declare a variable to temporarily record data by merging address bits
         * To efficiently use memory, the variable is declared inside block
         */
        {
            LOCAL_OFT_DATA_STRUCTURE local_aliasing_pc_temp;

            for(auto &aliasing_entry : local_oft)
            {
                // Merges address bits and map branches to the new aliased address
                app_pc pc = aliasing_entry.first;
                uintptr_t new_address = ((uintptr_t) pc) & address_merging_mask;
                auto &aliasing_map = local_aliasing_pc_temp[app_pc(new_address)];
            
                // Merge branch outcome counts for branches mapped to the same aliased address
                auto &old_counter  = aliasing_entry.second;

                for (auto &temp : old_counter)
                {
                    auto &old_hist  = temp.first;
                    auto &old_count = temp.second;
                    auto &temp_hist = aliasing_map[old_hist];

                    temp_hist.n_taken += old_count.n_taken;
                    temp_hist.n_not_taken += old_count.n_not_taken;
                }
            }

            local_oft.swap(local_aliasing_pc_temp);
        }

        /*
         * Preserve the address-merged OFT as the starting point for history-bit merging
         * The temporary data structures are scoped within this block to reduce memory usage
         */
        {
            // ********** Global History Part **********
            GLOBAL_OFT_DATA_STRUCTURE global_history_aliasing_oft;

            // Copy the address-merged OFT as the starting point for history-bit merging
            global_history_aliasing_oft.reserve(global_oft.size());
            for (auto &ent1 : global_oft)
            {
                global_history_aliasing_oft.emplace(ent1.first, ent1.second);
            }

            // ********** Local History Part **********
            LOCAL_OFT_DATA_STRUCTURE local_history_aliasing_oft;

            // Copy the address-merged OFT as the starting point for history-bit merging
            local_history_aliasing_oft.reserve(local_oft.size());
            for (auto &ent2 : local_oft)
            {
                local_history_aliasing_oft.emplace(ent2.first, ent2.second);
            }


            // ==== Inner loop ====
            for (int n_bit = HISTORY_LENGTH; n_bit >= 0; --n_bit)
            {
                // Retain the lower n_bit history bits to evaluate the corresponding history length
                uint32_t bit_merging_mask = (1u << n_bit) - 1;

                std::unordered_map<app_pc, double> tour_temporary_oft_aliasing;
        
                /*
                 * Declare a variable to temporarily record data by merging history bits
                 * To efficiently use memory, the variable is declared inside block
                 */
                // ********** Global History Part **********
                {
                    GLOBAL_OFT_DATA_STRUCTURE global_aliasing_hist_temp;

                    for(auto &temp_oft : global_history_aliasing_oft)
                    {
                        app_pc pc           = temp_oft.first;
                        auto &old_counter   = temp_oft.second;
                        auto &merged_map    = global_aliasing_hist_temp[pc];

                        for (auto &temp : old_counter)
                        {
                            uint32_t old_hist = temp.first;
                            uint32_t new_hist =  old_hist & bit_merging_mask;

                            auto &old_count = temp.second;
                            auto &temp_hist = merged_map[new_hist];

                            temp_hist.n_taken       += old_count.n_taken;
                            temp_hist.n_not_taken   += old_count.n_not_taken;
                        }
                    }

                    // Replace the current OFT with the history-merged OFT
                    global_history_aliasing_oft.swap(global_aliasing_hist_temp);
                }

                std::unordered_map<app_pc, double> tour_temporary_global_aliasing;

                // Loop for calculating branch entropies
                for (auto &g : global_history_aliasing_oft) 
                {
                    // Initialize Variables for Calculating Tour Entropy
                    total_instructions_per_addr_global_aliasing  = 0;
                    tour_entropy_per_addr_global_aliasing        = 0;

                    app_pc addr = g.first;

                    for (auto &a : g.second) 
                    {
                        GLOBAL_PATTERN hist = a.first;
                        auto &ctr = a.second;

                        // Compute the taken probability and corresponding linear branch entropy
                        double taken_probability    = double(ctr.n_taken) / double(ctr.n_taken + ctr.n_not_taken);
                        double linear_entropy       = 2 * std::min(taken_probability, (1 - taken_probability));

                        // Accumulate execution-weighted entropy for this branch address
                        tour_entropy_per_addr_global_aliasing        += double(ctr.n_taken + ctr.n_not_taken) * linear_entropy;
                        total_instructions_per_addr_global_aliasing  += (ctr.n_taken + ctr.n_not_taken);
                    }

                    // Store the global-history entropy for this branch address
                    tour_entropy_per_addr_global_aliasing = (tour_entropy_per_addr_global_aliasing / total_instructions_per_addr_global_aliasing);
                    tour_temporary_global_aliasing[addr] = tour_entropy_per_addr_global_aliasing;
                }

                // ********** Local History Part **********
                {
                    LOCAL_OFT_DATA_STRUCTURE local_aliasing_hist_temp;

                    for(auto &temp_oft : local_history_aliasing_oft)
                    {
                        app_pc pc           = temp_oft.first;
                        auto &old_counter   = temp_oft.second;
                        auto &merged_map    = local_aliasing_hist_temp[pc];

                        for (auto &temp : old_counter)
                        {
                            uint32_t old_hist = temp.first;
                            uint32_t new_hist = old_hist & bit_merging_mask;

                            auto &old_count = temp.second;
                            auto &temp_hist = merged_map[new_hist];

                            temp_hist.n_taken       += old_count.n_taken;
                            temp_hist.n_not_taken   += old_count.n_not_taken;
                        }
                    }
                    // Replace the current OFT with the history-merged OFT
                    local_history_aliasing_oft.swap(local_aliasing_hist_temp);
                }

                std::unordered_map<app_pc, double> tour_temporary_local_aliasing;

                // Loop for calculating branch entropies
                for (auto &l : local_history_aliasing_oft)
                {
                    // Initialize Variables for Tour Entropy
                    total_instructions_per_addr_local_aliasing  = 0;
                    tour_entropy_per_addr_local_aliasing        = 0;

                    app_pc addr = l.first;
            
                    // dr_printf("------------------Program Counter(%p)'s Merged Local OFT INFO------------------\n", addr);
                    for (auto &a : l.second)
                    {
                        LOCAL_PATTERN hist = a.first;
                        auto &ctr = a.second;

                        // Compute the taken probability and corresponding linear branch entropy
                        double taken_probability    = double(ctr.n_taken) / double(ctr.n_taken + ctr.n_not_taken);
                        double linear_entropy       = 2 * std::min( taken_probability, (1 - taken_probability) );

                        // Accumulate execution-weighted entropy for this branch address
                        tour_entropy_per_addr_local_aliasing       += double(ctr.n_taken + ctr.n_not_taken) * linear_entropy;
                        total_instructions_per_addr_local_aliasing += (ctr.n_taken + ctr.n_not_taken);
                    }

                    // Store the local-history entropy for this branch address
                    tour_entropy_per_addr_local_aliasing = (tour_entropy_per_addr_local_aliasing / total_instructions_per_addr_local_aliasing);
                    tour_temporary_local_aliasing[addr] = tour_entropy_per_addr_local_aliasing;
                }

                // Select the lower entropy between global- and local-history
                record_tour_entropy( tour_temporary_global_aliasing, tour_temporary_local_aliasing, tour_temporary_oft_aliasing);
                average_tour_entropy_aliasing( tour_temporary_oft_aliasing, address_length, n_bit);
            }
        }
    }

    // Print the tournament entropy for each address and history length
    for (auto &e : tour_entropy_list_aliasing) 
    {
        dr_printf("\n\n****************** Tournament Branch Entropy (Address Length = %d!!!) ******************\n\n", e.first);

        auto &histories = e.second;
        
        for(auto &counts : histories)
        {
            dr_printf("%d bit(s) length Entropy Value = %.6lf\n", counts.first, counts.second);
        }
    }

    dr_mutex_destroy(map_lock);
    drmgr_exit();
}

DR_EXPORT
void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    if(!drmgr_init())
        DR_ASSERT_MSG(false, "drmgr_init failed");

    map_lock = dr_mutex_create();
    
    // Register the basic-block instrumentation callback for conditional branches
    if (!drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL))
        DR_ASSERT_MSG(false, "fail to register event_app_instruction!");
    dr_register_exit_event(dr_exit);
}

