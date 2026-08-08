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

#define ADDRESS_LENGTH  7
#define HISTORY_LENGTH 48

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

typedef struct _transition_info_t {
    int         p_outcome       = -1;
    uint64_t    n_transition    = 0;
    uint64_t    n_execution     = 0; 
} transition_info_t;


// Declare Recording Global Pattern
#define GLOBAL_PATTERN uint64_t
#define HISTORY_MASK ( ( (uint64_t)1  <<  HISTORY_LENGTH ) - 1 )
GLOBAL_PATTERN global_pattern = 0;

// Declare "Outcome Frequency Table (OFT)" using Unodered Map (Hash Table) in C++
#define GLOBAL_OFT_DATA_STRUCTURE std::unordered_map<app_pc, std::unordered_map<GLOBAL_PATTERN, counter_per_branch_t>> 
GLOBAL_OFT_DATA_STRUCTURE global_oft;

#define GLOBAL_TRANSITION_DATA_STRUCTURE std::unordered_map<app_pc, std::unordered_map<GLOBAL_PATTERN, transition_info_t>>
GLOBAL_TRANSITION_DATA_STRUCTURE global_transition_oft;

// Declare Variables for Entropy Value from Global Histroy
uint64_t n_cbr_instructions = 0;
double branch_entropy = 0;


static void
cbr_count(void *drcontext, app_pc src, app_pc targ, int taken)
{
    dr_mutex_lock(map_lock);

    // Temporarily store global branch pattern
    GLOBAL_PATTERN history = global_pattern;

    uint64_t oft_address_mask = ( (uint64_t) 1 << ADDRESS_LENGTH ) - 1;
    uintptr_t masked_address = ((uintptr_t) src) & oft_address_mask;
    app_pc new_src = app_pc(masked_address);

    auto &taken_update = global_oft[new_src];
    auto &transition_update = global_transition_oft[new_src];

    auto &global_transition_counter = transition_update[history];
    
    if (taken)
    {
        // Update transition counter for taken case
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

        // Update the number of taken in "global OFT" and global branch pattern
        taken_update[history].n_taken++;
        global_pattern = ( ( history << 1 ) | 1 ) & HISTORY_MASK;
    }
    else
    {
        // Update transition counter for not-taken case
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

        // Update the number of not-taken in "global OFT" and global branch pattern
        taken_update[history].n_not_taken++;
        global_pattern = ( ( history << 1 ) | 0 ) & HISTORY_MASK;
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
    dr_printf("======================== Global Branch Entropy Value for Address Length = 7 and History Length = 48 =======================\n\n");

    // Calculating taken rate, transition rate, and branch entropy of a specific address and history length of each conditional branch
    for (auto &p : global_oft) 
    {
        app_pc addr = p.first;

        //update entropy info 
        auto &transition_comp   = global_transition_oft[addr];
        // double temp_transition  = 0;
        // double temp_value       = 0;

        for (auto &a : p.second) 
        {
            GLOBAL_PATTERN hist = a.first;
            auto &ctr = a.second;

            double temp_taken           = double(ctr.n_taken) / double(ctr.n_taken + ctr.n_not_taken); 
            double temp_linear_entropy  = 2 * std::min( temp_taken, ( 1 - temp_taken ) );

            auto &temp_transition_counter = transition_comp[hist];
            double temp_transition = double(temp_transition_counter.n_transition) / double(temp_transition_counter.n_execution);
            temp_transition = 2 * std::min(temp_transition, ( 1 - temp_transition ) );

            double temp_value = std::min(temp_linear_entropy, temp_transition);

            //Calculating final branch entropy
            branch_entropy += double(ctr.n_taken + ctr.n_not_taken) * temp_value;
            n_cbr_instructions += (ctr.n_taken + ctr.n_not_taken);
        }
    }

    // Calculating Final "Branch Entropy"
    branch_entropy = (branch_entropy / n_cbr_instructions);
    dr_printf("Branch Entropy = %.6lf\n", branch_entropy);

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
