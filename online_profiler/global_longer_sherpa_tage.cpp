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
#define ADDRESS_LENGTH  9
// Number of history bits used for indexing the OFT
#define HISTORY_LENGTH 84

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

// Global branch history and mask used to retain the most recent branch outcomes
#define GLOBAL_PATTERN __uint128_t
#define HISTORY_MASK ( (   (__uint128_t)1 <<  HISTORY_LENGTH )   -   1   ) // 0x000FFFFF
GLOBAL_PATTERN global_pattern = 0;

uint64_t address_merging_mask = ( (uint64_t) 1 << ADDRESS_LENGTH) - 1;

// OFT indexed by branch address and global history
#define GLOBAL_OFT_DATA_STRUCTURE std::unordered_map<app_pc, std::unordered_map<GLOBAL_PATTERN, counter_per_branch_t>> 
GLOBAL_OFT_DATA_STRUCTURE global_oft;

// Stores entropy-related information for each branch-history pair
#define GLOBAL_LINEAR_ENTROPY std::unordered_map<app_pc, std::unordered_map<GLOBAL_PATTERN, entropy_info_t>>
GLOBAL_LINEAR_ENTROPY global_branch_entropy;

// Total number of conditional branch executions used to normalize entropy
uint64_t n_cbr_instructions = 0;
// Accumulates the execution-weighted branch entropy
double branch_entropy = 0;


static void
cbr_count(void *drcontext, app_pc src, app_pc targ, int taken)
{
    dr_mutex_lock(map_lock);

    // Record the history preceding the current branch
    GLOBAL_PATTERN history = global_pattern;


    // Masking out the full address to fit the target address length
    uintptr_t new_address = ((uintptr_t) src) & address_merging_mask;

    // Update the number of taken in "global OFT" and global branch pattern
    auto &taken_update = global_oft[app_pc(new_address)];

    /*
     *  Record the branch outcome under the current global history,
     *  then update the history with the observed outcome
     */
    if (taken)
    {
        taken_update[history].n_taken++;
        global_pattern = (  (history << 1) | 1) & HISTORY_MASK;
    }
    else
    {
        taken_update[history].n_not_taken++;
        global_pattern = (  (history << 1) | 0) & HISTORY_MASK;
    }
    dr_mutex_unlock(map_lock);
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
    dr_printf("========================Branch Entropy Calculation for History Length = 84 =======================\n\n");

    // Compute the branch entropy for each branch-history pair
    for (auto &p : global_oft) 
    {
        app_pc addr = p.first;

        auto &taken_update = global_branch_entropy[addr];

        for (auto &a : p.second) 
        {
            GLOBAL_PATTERN hist = a.first;
            auto &ctr = a.second;

            // Compute the taken probability
            taken_update[hist].taken_probability = double(ctr.n_taken) / double(ctr.n_taken + ctr.n_not_taken);
            // Compute linear branch entropy from the taken probability
            taken_update[hist].linear_entropy = 2 * std::min(taken_update[hist].taken_probability, (1 - taken_update[hist].taken_probability));

            // Weight each branch-history entropy by its execution frequency
            branch_entropy += (ctr.n_taken + ctr.n_not_taken) * taken_update[hist].linear_entropy;

            // Accumulate the total number of conditional branch executions
            n_cbr_instructions += (ctr.n_taken + ctr.n_not_taken);
        }

    }

    // Normalize the accumulated entropy by the total number of branch executions
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
    
    // Register the basic-block instrumentation callback for conditional branches
    if (!drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL))
        DR_ASSERT_MSG(false, "fail to register event_app_instruction!");
    dr_register_exit_event(dr_exit);
}
