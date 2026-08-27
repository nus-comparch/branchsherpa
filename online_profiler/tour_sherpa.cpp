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
#define ADDRESS_LENGTH 13
// Number of history bits used for indexing the OFT
#define HISTORY_LENGTH 13

// Mutex protecting accesses to the global OFT
static void *map_lock;

// Counts taken and not-taken outcomes for a branch under a given history
typedef struct _counter_per_branch_t {
    uint64_t n_taken;
    uint64_t n_not_taken;
} counter_per_branch_t;

// Stores the previous outcome, transition count, and execution count
typedef struct _transition_info_t {
    int         p_outcome       = -1;
    uint64_t    n_transition    = 0;
    uint64_t    n_execution     = 0; 
} transition_info_t;


/* ******* Data structures and variables for the global history ******* */

// Global branch history and mask used to retain the most recent branch outcomes
#define GLOBAL_PATTERN uint32_t
#define HISTORY_MASK ( ( (uint32_t)1 << HISTORY_LENGTH ) - 1 ) 
GLOBAL_PATTERN global_pattern = 0;

// OFT indexed by branch address and global history
#define GLOBAL_OFT_DATA_STRUCTURE std::unordered_map<app_pc, std::unordered_map<GLOBAL_PATTERN, counter_per_branch_t>> 
GLOBAL_OFT_DATA_STRUCTURE global_oft;

// Stores transition information for each branch address and global history
#define GLOBAL_TRANSITION_DATA_STRUCTURE std::unordered_map<app_pc, std::unordered_map<GLOBAL_PATTERN, transition_info_t>>
GLOBAL_TRANSITION_DATA_STRUCTURE global_transition_oft;

// Stores the branch entropy of each branch based on global history
#define TOUR_PREDICTOR_GLOBAL std::unordered_map<app_pc, double>
TOUR_PREDICTOR_GLOBAL tour_predictor_entropy_global;


/* ******* Data structures and variables for local history ******* */

// Local branch history and mask used to retain the most recent branch outcomes
#define LOCAL_PATTERN uint32_t 

// Stores the local history pattern for each branch instruction
#define PER_BRANCH_PATTERN std::unordered_map<app_pc, LOCAL_PATTERN> 
PER_BRANCH_PATTERN pattern_per_branch;

// OFT indexed by branch address and local history
#define LOCAL_OFT_DATA_STRUCTURE std::unordered_map<app_pc, std::unordered_map<LOCAL_PATTERN, counter_per_branch_t>> 
LOCAL_OFT_DATA_STRUCTURE local_oft;

// Store outcome transition statistics for each branch instruction
#define LOCAL_TRANSITION_DATA_STRUCTURE std::unordered_map<app_pc, transition_info_t>
LOCAL_TRANSITION_DATA_STRUCTURE local_transition_oft;

// Stores the branch entropy of each branch based on local history
#define TOUR_PREDICTOR_LOCAL std::unordered_map<app_pc, double>
TOUR_PREDICTOR_LOCAL tour_predictor_entropy_local;

/* ******* Data structures and variables for tournament branch entropy ******* */

// Stores the selected entropy for each branch address
#define TOUR_ENTROPY_OFT std::unordered_map<app_pc, double>
TOUR_ENTROPY_OFT tour_entropy_oft;

double branch_entropy = 0;


static void
cbr_count(void *drcontext, app_pc src, app_pc targ, int taken)
{
    dr_mutex_lock(map_lock);

    /* Record the branch outcomes and transition statistics for both global and local history */

    /* Apply address aliasing by retaining only the configured number of address bits */
    uint64_t oft_address_mask = ( (uint64_t) 1 << ADDRESS_LENGTH ) - 1;
    uintptr_t masked_address = ((uintptr_t) src) & oft_address_mask;
    app_pc new_src = app_pc(masked_address);


    auto &global_taken_update       = global_oft[new_src];
    auto &global_transition_update  = global_transition_oft[new_src];
    GLOBAL_PATTERN temp_hist1       = global_pattern;

    auto &global_transition_counter = global_transition_update[temp_hist1];

    /*
     *  Record the transition statistics and branch outcome count under current global history,
     *  then update the global history with the observed outcome
     */
    if (taken)
    {
        // Update transition statistics for the taken outcome
        if(global_transition_counter.n_execution == 0)
        {
            global_transition_counter.n_execution++;
            global_transition_counter.p_outcome = 1;
        }
        else
        {
            global_transition_counter.n_execution++;

            if( global_transition_counter.p_outcome == 0   )
            {   
                global_transition_counter.n_transition++;  
                global_transition_counter.p_outcome = 1;
            }
                
        }

        // Update the taken count in the OFT and advance the global history
        global_taken_update[temp_hist1].n_taken++;
        global_pattern = (  (temp_hist1 << 1) | 1) & HISTORY_MASK;
    }
    else
    {
        // Update transition statistics for not-taken outcome
        if(global_transition_counter.n_execution == 0)
        {
            global_transition_counter.n_execution++;
            global_transition_counter.p_outcome = 0;
        }
        else
        {
            global_transition_counter.n_execution++;

            if( global_transition_counter.p_outcome == 1   )
            {   
                global_transition_counter.n_transition++;  
                global_transition_counter.p_outcome = 0;
            }
        }

        // Update the not-taken count in the OFT and advance the global history
        global_taken_update[temp_hist1].n_not_taken++;
        global_pattern = ( ( temp_hist1 << 1 ) | 0 ) & HISTORY_MASK;
    }
    
     // Record the history preceding the current branch
    LOCAL_PATTERN temp_hist2 = pattern_per_branch[new_src];

    auto &local_taken_update = local_oft[new_src];

    /*
     * **************** Important ****************  
     * Keep transition statistics for the original branch address
     * Address aliasing is applied when computing the final entropy
     */
    auto &local_transition_update = local_transition_oft[src];

    /*
     *  Record the transition statistics and branch outcome count under current local history,
     *  then update the local history with the observed outcome
     */
    if(taken)
    {
        // Update transition statistics for the taken outcome
        if(local_transition_update.n_execution == 0)
        {
            local_transition_update.n_execution++;
            local_transition_update.p_outcome = 1;
        }
        else
        {
            local_transition_update.n_execution++;

            if(local_transition_update.p_outcome == 0)
            {   
                local_transition_update.n_transition++;
                local_transition_update.p_outcome = 1;   
            }
        }

        // Update the taken count in the OFT and advance the local history
        local_taken_update[temp_hist2].n_taken++;
        pattern_per_branch[new_src] = ( ( temp_hist2 << 1 ) | 1 ) & HISTORY_MASK;
    }
    else
    {
        // Update transition statistics for the not-taken outcome
        if(local_transition_update.n_execution == 0)
        {
            local_transition_update.n_execution++;
            local_transition_update.p_outcome = 0;
        }
        else
        {
            local_transition_update.n_execution++;

            if(local_transition_update.p_outcome == 1)
            {   
                local_transition_update.n_transition++;   
                local_transition_update.p_outcome = 0;
            }
        }

        // Update the not-taken count in the OFT and advance the local history
        local_taken_update[temp_hist2].n_not_taken++;
        pattern_per_branch[new_src] = ( ( temp_hist2 << 1 ) | 0 ) & HISTORY_MASK;
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
average_tour_entropy(TOUR_ENTROPY_OFT &entries, int bit_length)
{
    double sum_tour_entropy = 0;

    // Average the tournament entropy values across all branch addresses
    for (auto &t : entries)
    {
        sum_tour_entropy += t.second;
    }
    branch_entropy = sum_tour_entropy / entries.size();
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
    // dr_printf("======================== Tour Branch Entropy Value for Address Length = 13 and History Length = 13 =======================\n\n");
    
    /*
     * Compute entropy for the global- and local-history
     *
     * Select the lower entropy between the global- and local-history
     * to obtain the tournament entropy for each branch 
     */
    for (auto &p : global_oft) 
    {
        app_pc addr = p.first;

        //update entropy info 
        auto &transition_comp = global_transition_oft[addr];
        // double temp_transition  = 0;
        

        double      tour_entropy_per_addr_global        = 0;
        uint64_t    total_instructions_per_addr_global  = 0;


        for (auto &a : p.second) 
        {
            GLOBAL_PATTERN hist = a.first;
            auto &ctr = a.second;

            // Compute linear entropy from the taken rate
            double temp_taken = double(ctr.n_taken) / double(ctr.n_taken + ctr.n_not_taken);
            double temp_linear_entropy = 2 * std::min( temp_taken, ( 1 - temp_taken ) );

            // Compute linear entropy from the transition rate
            auto &temp_transition_counter = transition_comp[hist];
            double temp_transition = double(temp_transition_counter.n_transition) / double(temp_transition_counter.n_execution);
            temp_transition = 2 * std::min(temp_transition, (1 - temp_transition));

            double temp_value = std::min(temp_linear_entropy, temp_transition);

            // Accumulate execution-weighted entropy across histories
            tour_entropy_per_addr_global += double(ctr.n_taken + ctr.n_not_taken) * temp_value;
            // Accumulate the total number of branch executions for normalization
            total_instructions_per_addr_global += (ctr.n_taken + ctr.n_not_taken);
        }

        // Normalize the execution-weighted entropy by the total number of instructions
        tour_predictor_entropy_global[addr] = (tour_entropy_per_addr_global / double(total_instructions_per_addr_global));
    }
    

    for (auto &p : local_oft) 
    {
        app_pc addr = p.first;

        // Update entropy info 
        double  temp_transition             = 0;
        int     same_ctr                    = 0;
        double  temp_transition_per_addr    = 0;
        double  temp_linear_transition      = 0;
        double  genuine_branch_entropy      = 0;

        double      tour_entropy_per_addr_local         = 0;
        uint64_t    total_instructions_per_addr_local   = 0;

        /*
         * Compute the average transition linear entropy of branches 
         * that are mapped to the same address
         */
        for(auto &m : local_transition_oft)
        {
            app_pc temp_addr = m.first;

            uint64_t address_mask = ( (uint64_t) 1 << ADDRESS_LENGTH ) - 1;
            uintptr_t temp_address = ((uintptr_t) temp_addr ) & address_mask;
            app_pc masked_src = app_pc(temp_address);

            // Select the branches belonging to the same aliased address
            if(masked_src == addr)
            {
                ++same_ctr; 
                temp_transition_per_addr = double(m.second.n_transition) / double(m.second.n_execution); 
                temp_transition_per_addr = 2 * std::min( temp_transition_per_addr, (1 - temp_transition_per_addr) ); 
                temp_linear_transition += temp_transition_per_addr;
            }
        }

        // Average transition entropy across branches in the same address
        temp_linear_transition = temp_linear_transition / same_ctr;

        for (auto &kv : p.second) 
        {
            LOCAL_PATTERN hist = kv.first;
            auto &ctr = kv.second;

            // Compute the taken rate and its corresponding linear branch entropy
            double temp_taken_rate = double(ctr.n_taken) / double(ctr.n_taken + ctr.n_not_taken);
            double temp_linear_entropy = 2 * std::min( temp_taken_rate, ( 1 - temp_taken_rate ) );

            // Combine taken rate and transition rate using the minimum value
            genuine_branch_entropy = std::min(temp_linear_entropy, temp_linear_transition);

            // Accumulate execution-weighted combined branch entropy
            tour_entropy_per_addr_local       += double(ctr.n_taken + ctr.n_not_taken) * genuine_branch_entropy;
            // Accumulate the total number of conditional branch executions
            total_instructions_per_addr_local += (ctr.n_taken + ctr.n_not_taken);

        }

        // Store the execution-weighted entropy for the local-history
        tour_predictor_entropy_local[addr] = (tour_entropy_per_addr_local / double(total_instructions_per_addr_local));
    }

    /*
     * Select the lower entropy between the global- and local-history
     * for each branch address  
     */
    record_tour_entropy(tour_predictor_entropy_global, tour_predictor_entropy_local, tour_entropy_oft);

    // Average the tournament entropy values across all branch address
    average_tour_entropy(tour_entropy_oft, HISTORY_LENGTH);

    dr_printf("Tournament Branch Entropy Value = %.6lf\n", branch_entropy);

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

