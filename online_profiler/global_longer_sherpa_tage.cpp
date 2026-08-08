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

#define ADDRESS_LENGTH  9
#define HISTORY_LENGTH2 84

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

#define GLOBAL_PATTERN2 __uint128_t
#define HISTORY_MASK2 ( (   (__uint128_t)1 <<  HISTORY_LENGTH2 )   -   1   ) // 0x000FFFFF
GLOBAL_PATTERN2 global_pattern2 = 0;

uint64_t address_merging_mask = ( (uint64_t) 1 << ADDRESS_LENGTH) - 1;

#define GLOBAL_OFT_DATA_STRUCTURE2 std::unordered_map<app_pc, std::unordered_map<GLOBAL_PATTERN2, counter_per_branch_t>> 
GLOBAL_OFT_DATA_STRUCTURE2 global_oft2;

#define GLOBAL_LINEAR_ENTROPY2 std::unordered_map<app_pc, std::unordered_map<GLOBAL_PATTERN2, entropy_info_t>>
GLOBAL_LINEAR_ENTROPY2 global_linear_entropy_oft2;

// Declare Variables for Entropy Value from Global Histroy
uint64_t n_cbr_instructions = 0;
double branch_entropy2 = 0;


static void
cbr_count(void *drcontext, app_pc src, app_pc targ, int taken)
{
    dr_mutex_lock(map_lock);

    // Temporary store global_pattern history in history
    GLOBAL_PATTERN2 history2 = global_pattern2;


    // Update the number of "taken" branches in the global OFT
    uintptr_t new_address = ((uintptr_t) src) & address_merging_mask;

    // auto &taken_update2 = global_oft2[src];
    auto &taken_update2 = global_oft2[app_pc(new_address)];

    if (taken)
    {
        taken_update2[history2].n_taken++;
        
        //Update the Global Pattern
        global_pattern2 = (  (history2 << 1) | 1) & HISTORY_MASK2;
    }
    else
    {
        taken_update2[history2].n_not_taken++;

        //Update the Global Pattern
        global_pattern2 = (  (history2 << 1) | 0) & HISTORY_MASK2;
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
    dr_printf("======================== Entropy Calculation for History Length = 84 =======================\n\n");

    n_cbr_instructions = 0;

    // Printing Out All of the Logs in the Unordered Map
    for (auto &p : global_oft2) 
    {
        app_pc addr = p.first;

        //update entropy info 
        auto &taken_update = global_linear_entropy_oft2[addr];

        for (auto &a : p.second) 
        {
            GLOBAL_PATTERN2 hist = a.first;
            auto &ctr = a.second;

            //update entropy info 
            taken_update[hist].taken_probability = double(ctr.n_taken) / double(ctr.n_taken + ctr.n_not_taken);
            taken_update[hist].linear_entropy = 2 * std::min(taken_update[hist].taken_probability, (1 - taken_update[hist].taken_probability));

            // Calculating Final "Branch Entropy" from Global History
            branch_entropy2 += (ctr.n_taken + ctr.n_not_taken) * taken_update[hist].linear_entropy;

            // Counting the total number of cbr instructions
            n_cbr_instructions += (ctr.n_taken + ctr.n_not_taken);
        }

    }

    // Calculating Final "Branch Entropy"
    branch_entropy2 = (branch_entropy2 / n_cbr_instructions);
    // dr_printf("Total Instruction # at = %u\n", n_cbr_instructions);
    dr_printf("Branch Entropy = %.6lf\n", branch_entropy2);

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
