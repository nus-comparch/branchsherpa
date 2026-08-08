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

// Declare Lock for Preventing Contention in Local "Outcome Frequency Table (OFT)"
static void *map_lock;

// Declare for Two Counters (i.e., "taken" and "not taken") for each branch
typedef struct _counter_per_branch_t {
    uint64_t n_taken;
    uint64_t n_not_taken;
} counter_per_branch_t;

// Declare "Taken Probability" and "Global Entropy" for each entry in OFT
typedef struct _entropy_info_t {
    double taken_probability;
    double linear_entropy;
} entropy_info_t;

// Declare for Recording Local Pattern
#define LOCAL_PATTERN uint32_t
#define HISTORY_MASK ( ( 1u << HISTORY_LENGTH ) - 1 ) 

// Storing "history pattern" for each branch instruction
#define PER_BRANCH_PATTERN std::unordered_map<app_pc, LOCAL_PATTERN> 
PER_BRANCH_PATTERN pattern_per_branch;

// Declare an "Outcome Frequency Table (OFT)" using unodered map (hash table) in C++
#define LOCAL_OFT_DATA_STRUCTURE std::unordered_map<app_pc, std::unordered_map<LOCAL_PATTERN, counter_per_branch_t>> 
LOCAL_OFT_DATA_STRUCTURE local_oft;

// Declare an data structure to compute branch entropy values
#define LOCAL_LINEAR_ENTROPY std::unordered_map<app_pc, std::unordered_map<LOCAL_PATTERN, entropy_info_t>>
LOCAL_LINEAR_ENTROPY local_branch_entropy;

// Declare Variables for Entropy Value from local Histroy
uint64_t n_cbr_instructions = 0;
double branch_entropy = 0;


static void
cbr_count(void *drcontext, app_pc src, app_pc targ, int taken)
{
    dr_mutex_lock(map_lock);

    // Temporarily store local branch pattern
    LOCAL_PATTERN history = pattern_per_branch[src];

    // Update the number of taken and not-taken in "local OFT" and local branch pattern
    auto &taken_update = local_oft[src];
    if (taken)
    {
        taken_update[history].n_taken++;
        pattern_per_branch[src] = (  ( history << 1 ) | 1 ) & HISTORY_MASK;
    }
    else
    {
        taken_update[history].n_not_taken++;        
        pattern_per_branch[src] = (  ( history << 1 ) | 0 ) & HISTORY_MASK;
    }
    dr_mutex_unlock(map_lock);
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data)
{
    // Instrument on conditional branch instructions
    if(!instr_is_cbr(instr))
        return DR_EMIT_DEFAULT;
    dr_insert_cbr_instrumentation(drcontext, bb, instr, (void*)cbr_count);

    return DR_EMIT_DEFAULT;
}

void
dr_exit(void)
{
    // Calculating taken probability and branch entropy of a specific global history of each conditional branch
    for (auto &p : local_oft) 
    {
        app_pc addr = p.first;

        //update entropy info 
        auto &taken_update = local_branch_entropy[addr];

        for (auto &kv : p.second) 
        {
            LOCAL_PATTERN hist = kv.first;
            auto &ctr = kv.second;

            // Computing taken rate and linear branch entropy
            taken_update[hist].taken_probability = double(ctr.n_taken) / double(ctr.n_taken + ctr.n_not_taken);
            taken_update[hist].linear_entropy = 2 * std::min(taken_update[hist].taken_probability, (1 - taken_update[hist].taken_probability));

            branch_entropy += (ctr.n_taken + ctr.n_not_taken) * taken_update[hist].linear_entropy;

            // Counting the total number of cbr instructions
            n_cbr_instructions += (ctr.n_taken + ctr.n_not_taken);
        }
    }

    //Calculating Final "Branch Entropy"
    branch_entropy =  (branch_entropy / n_cbr_instructions);
    dr_printf("Final Branch Entropy Value = %.6lf\n", branch_entropy);

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

