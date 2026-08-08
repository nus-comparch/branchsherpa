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

#define ADDRESS_LENGTH 48
#define HISTORY_LENGTH 20

// Declare Lock for Preventing Contention in Global "Outcome Frequency Table (OFT)"
static void *map_lock;

// Declare counters (i.e., "taken", "not taken", and "transitions") for each conditional branch
typedef struct _counter_per_branch_t {
    uint64_t n_taken;
    uint64_t n_not_taken;
} counter_per_branch_t;

// Declare variables to compute taken rate and transition rate
typedef struct _entropy_info_t {
    double taken_probability;
    double linear_entropy;
} entropy_info_t;


// Declare variables and a mask to record a global pattern 
#define GLOBAL_PATTERN uint32_t
#define HISTORY_MASK ( ( 1u << HISTORY_LENGTH ) - 1 )
GLOBAL_PATTERN global_pattern = 0;


// Declare an "Outcome Frequency Table (OFT)" using unodered map (hash table) in C++
#define GLOBAL_OFT_DATA_STRUCTURE std::unordered_map<app_pc, std::unordered_map<GLOBAL_PATTERN, counter_per_branch_t>> 
GLOBAL_OFT_DATA_STRUCTURE global_oft;

// Declare a data structure to compute taken rate and linear branch entropy
#define GLOBAL_TEMPORARY_ENTROPY std::unordered_map<app_pc, std::unordered_map<GLOBAL_PATTERN, entropy_info_t>>

// Declare a data structure to store branch entropy values for different address and history lengths
#define GLOBAL_ALIASING_ENTROPY_LIST std::unordered_map<int, std::unordered_map<int, double>>
GLOBAL_ALIASING_ENTROPY_LIST global_aliasing_entropy_list;


// Declare variables for global entropy value
uint64_t n_cbr_instructions = 0;
double branch_entropy = 0;


static void
cbr_count(void *drcontext, app_pc src, app_pc targ, int taken)
{
    dr_mutex_lock(map_lock);

    // Temporarily store global branch pattern
    GLOBAL_PATTERN history = global_pattern;

    // Update the number of taken in "global OFT" and global branch pattern
    auto &taken_update = global_oft[src];
    if (taken)
    {
        taken_update[history].n_taken++;
        global_pattern = (  ( history << 1 ) | 1 ) & HISTORY_MASK;
    }
    else
    {
        taken_update[history].n_not_taken++;
        global_pattern = (  ( history << 1 ) | 0 ) & HISTORY_MASK;
    }
    dr_mutex_unlock(map_lock);
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data)
{
    // Instruemnt on conditional branch instructions
    if(!instr_is_cbr(instr))
        return DR_EMIT_DEFAULT;
    dr_insert_cbr_instrumentation(drcontext, bb, instr, (void*)cbr_count);
    
    return DR_EMIT_DEFAULT;
}

void
dr_exit(void)
{ 
    // Calculating branch entropy by applying optimizations in Linear Branch Entropy paper
    
    /*
     * Outer loop: merging address bits (first optimization)
     * Inner loop: mering history bits (second optimization)
     * Please refere "Linear Branch Entropy" paper for more information
     */

    // ==== outer loop ====
    for(int address_length = ADDRESS_LENGTH; address_length >= 0; --address_length)
    {
        uint64_t address_merging_mask = ( (uint64_t) 1 << address_length) - 1;

        /*
         * Declare a variable to temporarily record data by merging address bits
         * To efficiently use memory, the variable is declared inside block
        */ 
        {
            GLOBAL_OFT_DATA_STRUCTURE aliasing_pc_temp;

            for(auto &aliasing_entry : global_oft)
            {
                // Updating Address Length and Recording It to Newly Created OFT
                app_pc pc = aliasing_entry.first;
                uintptr_t new_address = ((uintptr_t) pc) & address_merging_mask;
                auto &aliasing_map = aliasing_pc_temp[app_pc(new_address)];
            
                // Updating Branch Outcome to Newly Created OFT
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
            global_oft.swap(aliasing_pc_temp);
        }

        /*
         * After applying address merging, copy the oft to the new data structure for history bit merging
         * For memory efficiency, declare a variable inside block
        */ 
        {
            GLOBAL_OFT_DATA_STRUCTURE history_aliasing_oft;

            // Copying the data structure after applying address merging
            history_aliasing_oft.reserve(global_oft.size());
            for (auto &ent : global_oft)
            {
                history_aliasing_oft.emplace(ent.first, ent.second);
            }

            // ==== Inner loop ====
            for (int n_bit = HISTORY_LENGTH; n_bit >= 0; --n_bit)
            {
                // Merging Two History Bits for Smaller Number of History Bits
                uint32_t bit_merging_mask = (1u << n_bit) - 1;

                // Initializing variables related to branch entropy calculation
                branch_entropy = 0;
                n_cbr_instructions = 0;
    
                /*
                 * Declare a variable to temporarily record data by merging history bits
                 * To efficiently use memory, the variable is declared inside block
                */
                {
                    GLOBAL_OFT_DATA_STRUCTURE aliasing_hist_temp;

                    for(auto &temp_oft : history_aliasing_oft)
                    {
                        app_pc pc           = temp_oft.first;
                        auto &old_counter   = temp_oft.second;
                        auto &merged_map    = aliasing_hist_temp[pc];

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
                    history_aliasing_oft.swap(aliasing_hist_temp);
                }
            
                // Loop for calculating branch entropies
                for (auto &t : history_aliasing_oft) 
                {
                    app_pc addr = t.first;

                    // Declare a variable to record taken rate and linear branch entropy
                    GLOBAL_TEMPORARY_ENTROPY global_entropy_oft; // global_aliasing_entropy_oft
                    auto &taken_update = global_entropy_oft[addr];

                    for (auto &a : t.second) 
                    {
                        GLOBAL_PATTERN hist = a.first;
                        auto &ctr = a.second;

                        uint64_t total_count = (uint64_t)ctr.n_taken + (uint64_t)ctr.n_not_taken;
                        if (total_count == 0) 
                        {
                            taken_update[hist].taken_probability = 0.0;
                            taken_update[hist].linear_entropy = 0.0;
                            dr_printf("Warning: Zero counts at PC=%p, hist=%u, skipping entropy calculation\n", addr, hist);
                            continue;
                        }
                        else
                        {
                            //update entropy info 
                            taken_update[hist].taken_probability = double(ctr.n_taken) / double(ctr.n_taken + ctr.n_not_taken);
                            taken_update[hist].linear_entropy = 2 * std::min(taken_update[hist].taken_probability, (1 - taken_update[hist].taken_probability));
                        }

                        if (taken_update[hist].linear_entropy < 0) 
                        {
                            dr_printf("Warning: Negative entropy at PC=%p, hist=%u, p=%.6f\n", addr, hist, taken_update[hist].linear_entropy);
                            taken_update[hist].linear_entropy = 0.0; // Force to 0
                            continue;
                        }

                        // Calculating Final "Branch Entropy"
                        branch_entropy += (ctr.n_taken + ctr.n_not_taken) * taken_update[hist].linear_entropy;

                        n_cbr_instructions += (ctr.n_taken + ctr.n_not_taken);
                    }

                }
                // dr_printf("Total Instruction # at = %u\n\n", n_cbr_instructions);
                branch_entropy = (branch_entropy / n_cbr_instructions);

                // Updating Entropy Value for Specific Address and History Length
                auto &update_aliasing = global_aliasing_entropy_list[address_length];
                update_aliasing[n_bit] = branch_entropy;
            }
        }
    }

    for (auto &e : global_aliasing_entropy_list) 
    {
        dr_printf("\n\n****************** Global Branch Entropy Value (Address Length = %d!!!) ******************\n\n", e.first);

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
    
    // Instrumentation for Conditional Branch Instructions Every Basic Block
    if (!drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL))
        DR_ASSERT_MSG(false, "fail to register event_app_instruction!");
    dr_register_exit_event(dr_exit);
}
