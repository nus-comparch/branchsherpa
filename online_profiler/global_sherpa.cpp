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
// #define MINSERT instrlist_meta_preinsert

// Declare Lock for Preventing Contention in Global "Outcome Frequency Table (OFT)"
static void *map_lock;

// Declare Two Counters (i.e., "taken" and "not taken") for each branch
typedef struct _counter_per_branch_t {
    uint64_t n_taken;
    uint64_t n_not_taken;
} counter_per_branch_t;

// Declare "Taken Probability" and "Global Entropy" for each entry in OFT
typedef struct _entropy_info_t {
    double taken_probability;
    double linear_entropy;
} entropy_info_t;

typedef struct _transition_info_t {
    int         p_outcome;
    uint64_t    n_transition;
    uint64_t    n_execution; 
} transition_info_t;


// Declare Recording Global Pattern
#define GLOBAL_PATTERN uint32_t
#define HISTORY_MASK ((1u<<HISTORY_LENGTH)-1) // 0x000FFFFF
GLOBAL_PATTERN global_pattern = 0;

// Declare "Outcome Frequency Table (OFT)" using Unodered Map (Hash Table) in C++
#define GLOBAL_OFT_DATA_STRUCTURE std::unordered_map<app_pc, std::unordered_map<GLOBAL_PATTERN, counter_per_branch_t>> 
GLOBAL_OFT_DATA_STRUCTURE global_oft;
#define OFT_DATA_STRUCTURE std::unordered_map<GLOBAL_PATTERN, counter_per_branch_t>

#define GLOBAL_TRANSITION_DATA_STRUCTURE std::unordered_map<int, std::unordered_map<app_pc, std::unordered_map<int, std::unordered_map<GLOBAL_PATTERN, transition_info_t>>>>
GLOBAL_TRANSITION_DATA_STRUCTURE global_transition_oft;

#define GLOBAL_LINEAR_ENTROPY std::unordered_map<app_pc, std::unordered_map<GLOBAL_PATTERN, entropy_info_t>>
GLOBAL_LINEAR_ENTROPY global_linear_entropy_oft;

// Declare "Temporary Data Structure" for merging history bits
#define GLOBAL_TEMPORARY_STRUCTURE std::unordered_map<app_pc, std::unordered_map<GLOBAL_PATTERN, counter_per_branch_t>>
GLOBAL_TEMPORARY_STRUCTURE global_merged_oft;

#define GLOBAL_TEMPORARY_ENTROPY std::unordered_map<app_pc, std::unordered_map<GLOBAL_PATTERN, entropy_info_t>>
// GLOBAL_TEMPORARY_ENTROPY global_merged_entropy_oft;

// Recording Final Entropy Value for Each length of histroy bit (20, 19, 18, ..., 2, 1, 0)
#define GLOBAL_ENTROPY_LIST std::unordered_map<int, double>
GLOBAL_ENTROPY_LIST global_entropy_list;


// Declare "Temporary Data Structure" for merging address bits
#define GLOBAL_ALIASING_OFT std::unordered_map<app_pc, std::unordered_map<GLOBAL_PATTERN, counter_per_branch_t>>
GLOBAL_ALIASING_OFT global_aliasing_oft;
GLOBAL_ALIASING_OFT address_aliasing_oft;

#define GLOBAL_ALIASING_ENTROPY_LIST std::unordered_map<int, std::unordered_map<int, double>>
GLOBAL_ALIASING_ENTROPY_LIST global_aliasing_entropy_list;

// Declare Variables for Entropy Value from Global Histroy
uint64_t n_cbr_instructions = 0;
double branch_entropy = 0;

bool lookup(int addr_len, app_pc src, int hist_len, GLOBAL_PATTERN history)
{
    auto &temp_address_length   = global_transition_oft[addr_len];
    auto &temp_address          = temp_address_length[src];
    auto &temp_update           = temp_address[hist_len];
    // auto &temp_update           = temp_address[history];

    if(temp_update.find(history) != temp_update.end())
    {   return false;    }
    else
    {   return true;     }
}

static void
cbr_count(void *drcontext, app_pc src, app_pc targ, int taken)
{
    dr_mutex_lock(map_lock);

    // Temporary store global_pattern history in history
    GLOBAL_PATTERN history = global_pattern;

    for(int num = 48; num >= 1; --num)
    {
        uint64_t transition_address_mask = ( (uint64_t) 1 << num ) - 1;
        uintptr_t masked_address = ((uintptr_t) src) & transition_address_mask;
        app_pc new_src = app_pc(masked_address);

        auto &transition_address_length = global_transition_oft[num];
        auto &transition_address        = transition_address_length[new_src];


        for(int n_history = 20; n_history >= 0; --n_history)
        {
            uint32_t transition_mask = (1u << n_history) - 1;
            uint32_t temp_hist =  history & transition_mask;

            auto &transition_update = transition_address[n_history];

            if(taken)
            {
                if( lookup(num, new_src, n_history, temp_hist) )
                {
                    transition_update[temp_hist].n_execution++;
                    transition_update[temp_hist].p_outcome = 1;
                }
                else
                {
                    transition_update[temp_hist].n_execution++;

                    if( transition_update[temp_hist].p_outcome == 0   )
                    {   transition_update[temp_hist].n_transition++;  }
                
                    transition_update[temp_hist].p_outcome = 1;
                }
            }
            else
            {
                if( lookup(num, new_src, n_history, temp_hist) )
                {
                    transition_update[temp_hist].n_execution++;
                    transition_update[temp_hist].p_outcome = 0;
                }
                else
                {
                    transition_update[temp_hist].n_execution++;

                    if( transition_update[temp_hist].p_outcome == 1   )
                    {   transition_update[temp_hist].n_transition++;  }
                
                    transition_update[temp_hist].p_outcome = 0;
                }
            }
        }
    }

    // Update the number of "taken" branches in the global OFT
    auto &taken_update = global_oft[src];

    if (taken)
    {
        taken_update[history].n_taken++;
        //Update the Global Pattern
        global_pattern = (  (history << 1) | 1) & HISTORY_MASK;
    }
    else
    {
        taken_update[history].n_not_taken++;
        //Update the Global Pattern
        global_pattern = (  (history << 1) | 0) & HISTORY_MASK;
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
    global_aliasing_oft.reserve(global_oft.size());
    for (auto &aliasing_entry : global_oft)
    {
        global_aliasing_oft.emplace(aliasing_entry.first, aliasing_entry.second);
    }

    for(int address_length = ADDRESS_LENGTH; address_length >= 0; --address_length)
    {
        /* ========================== Merging Address Legnth for Aliasing ========================== */

        // Merging History Length for Smaller Number of Branch Instruction Address Bits
        uint64_t address_merging_mask = ( (uint64_t) 1 << address_length) - 1;

        // Declare New OFT for Reduced Length of Address
        GLOBAL_OFT_DATA_STRUCTURE aliasing_pc_oft;

        for(auto &aliasing_entry : global_aliasing_oft)
        {
            // Updating Address Length and Recording It to Newly Created OFT
            app_pc pc = aliasing_entry.first;
            uintptr_t new_address = ((uintptr_t) pc) & address_merging_mask;
            auto &aliasing_map = aliasing_pc_oft[app_pc(new_address)];
            
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

        global_aliasing_oft.swap(aliasing_pc_oft);

        address_aliasing_oft.clear();
        address_aliasing_oft.reserve(global_aliasing_oft.size());
        for (auto &aliasing_entry : global_aliasing_oft)
        {
            address_aliasing_oft.emplace(aliasing_entry.first, aliasing_entry.second);
        }

        for (int n_bit = HISTORY_LENGTH; n_bit >= 0; --n_bit)
        {
            // Merging Two History Bits for Smaller Number of History Bits
            uint32_t bit_merging_mask = (1u << n_bit) - 1;

            // // Initializing "Branch Entropy" Value for every history bit length
            branch_entropy = 0;
            n_cbr_instructions = 0;
    
            GLOBAL_OFT_DATA_STRUCTURE new_oft;

            for(auto &temp_oft : address_aliasing_oft)
            {
                // GLOBAL_OFT_DATA_STRUCTURE new_oft;

                app_pc pc           = temp_oft.first;
                auto &old_counter   = temp_oft.second;
                auto &merged_map    = new_oft[pc];

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
            address_aliasing_oft.swap(new_oft);

            auto &temp_transition1 = global_transition_oft[address_length];
            
            // Calculating Branch Entropy
            for (auto &t : address_aliasing_oft) 
            {
                app_pc addr = t.first;

                //update entropy info 
                GLOBAL_TEMPORARY_ENTROPY global_aliasing_entropy_oft;
                auto &taken_update = global_aliasing_entropy_oft[addr];

                auto &temp_transition2 = temp_transition1[addr];
                auto &temp_transition3 = temp_transition2[n_bit];

                for (auto &a : t.second) 
                {
                    GLOBAL_PATTERN hist = a.first;
                    auto &ctr = a.second;

                    double temp_final = 0;
                    double temp_transition_rate = 0;


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

                        temp_transition_rate = static_cast<double>(temp_transition3[hist].n_transition) / static_cast<double>(temp_transition3[hist].n_execution);
                        temp_transition_rate = 2 * std::min(temp_transition_rate, 1 - temp_transition_rate);

                        temp_final = std::min(taken_update[hist].linear_entropy, temp_transition_rate);
                    }

                    if (taken_update[hist].linear_entropy < 0) 
                    {
                        dr_printf("Warning: Negative entropy at PC=%p, hist=%u, p=%.6f\n", addr, hist, taken_update[hist].linear_entropy);
                        taken_update[hist].linear_entropy = 0.0; // Force to 0
                        continue;
                    }


                    // Calculating Final "Branch Entropy"
                    branch_entropy += (ctr.n_taken + ctr.n_not_taken) * temp_final;

                    n_cbr_instructions += (ctr.n_taken + ctr.n_not_taken);

                    // dr_printf("PC = %p \t history=%u: \t taken=%u, not_taken=%u\n\n",
                    //           addr, hist, ctr.n_taken, ctr.n_not_taken);
                }

            }

            dr_printf("Total Instruction # at = %u\n\n", n_cbr_instructions);

            branch_entropy = (branch_entropy / n_cbr_instructions);

            // Updating Entropy Value for Specific Address and History Length
            auto &update_aliasing = global_aliasing_entropy_list[address_length];
            update_aliasing[n_bit] = branch_entropy;
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
