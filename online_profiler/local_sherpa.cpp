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
#define ADDRESS_LENGTH 2
// Number of history bits used for indexing the OFT
#define HISTORY_LENGTH 10

// Mutex protecting shared profiling data structures
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

// Stores the previous outcome, transition count, and execution count
typedef struct _transition_info_t {
    int         p_outcome       = -1;
    uint64_t    n_transition    = 0;
    uint64_t    n_execution     = 0; 
} transition_info_t;

// Local branch history and mask used to retain the most recent branch outcomes
#define LOCAL_PATTERN uint32_t
#define HISTORY_MASK ( ( ( uint32_t ) 1 << HISTORY_LENGTH ) - 1 )

// Stores the local history pattern for each branch instruction
#define PER_BRANCH_PATTERN std::unordered_map<app_pc, LOCAL_PATTERN> 
PER_BRANCH_PATTERN pattern_per_branch;

// OFT indexed by branch address and local history
#define LOCAL_OFT_DATA_STRUCTURE std::unordered_map<app_pc, std::unordered_map<LOCAL_PATTERN, counter_per_branch_t>> 
LOCAL_OFT_DATA_STRUCTURE local_oft;

// Store outocme transition statistics for each branch instruction
#define LOCAL_TRANSITION_DATA_STRUCTURE std::unordered_map<app_pc, transition_info_t>
LOCAL_TRANSITION_DATA_STRUCTURE local_transition_oft;

// Stores entropy-related information for each branch-history pair
#define LOCAL_LINEAR_ENTROPY std::unordered_map<app_pc, std::unordered_map<LOCAL_PATTERN, entropy_info_t>>
LOCAL_LINEAR_ENTROPY local_linear_entropy_oft;

// Total number of conditional branch executions used to normalize entropy
uint64_t n_cbr_instructions = 0;
// Accumulates the execution-weighted branch entropy
double branch_entropy = 0;


static void
cbr_count(void *drcontext, app_pc src, app_pc targ, int taken)
{
    dr_mutex_lock(map_lock);

    // Map the branch address to the configured address length
    uint64_t oft_address_mask = ( (uint64_t) 1 << ADDRESS_LENGTH ) - 1;
    uintptr_t masked_address = ((uintptr_t) src) & oft_address_mask;
    app_pc new_src = app_pc(masked_address);


    // Record the history preceding the current branch
    LOCAL_PATTERN history = pattern_per_branch[new_src];

    auto &taken_update = local_oft[new_src];

    /*
     * **************** Important ****************  
     * Keep transition statistics for the original branch address
     * Address aliasing is applied when computing the final entropy
     */
    auto &transition_update = local_transition_oft[src];

    /*
     *  Record the transition statistics and branch outcome count,
     *  then update the local history with the observed outcome
     */
    if (taken)
    {
        // Update transition statistics for the taken outcome
        if(transition_update.n_execution == 0)
        {
            transition_update.n_execution++;
            transition_update.p_outcome = 1;
        }
        else
        {
            transition_update.n_execution++;

            if(transition_update.p_outcome == 0)
            {   
                transition_update.n_transition++;
                transition_update.p_outcome = 1;   
            }
        }

        // Update the taken count in the OFT and advance the local history
        taken_update[history].n_taken++;
        pattern_per_branch[new_src] = (  ( history << 1 ) | 1 ) & HISTORY_MASK;
    }
    else
    {
        // Update transition statistics for not-taken outcome
        if(transition_update.n_execution == 0)
        {
            transition_update.n_execution++;
            transition_update.p_outcome = 0;
        }
        else
        {
            transition_update.n_execution++;
            if(transition_update.p_outcome == 1)
            {   
                transition_update.n_transition++;  
                transition_update.p_outcome = 0; 
            }
        }

        // Update the not-taken count in the OFT and advance the local history
        taken_update[history].n_not_taken++;
        pattern_per_branch[new_src] = (  ( history << 1 ) | 0 ) & HISTORY_MASK;
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
    dr_printf("======================== Local Branch Entropy Value for Address Length = 2 and History Length = 10 =======================\n\n");

    // Compute entropy byt combing taken rate and transition rate 
    for (auto &p : local_oft) 
    {
        app_pc addr = p.first;

        //update entropy info 
        auto &taken_update = local_linear_entropy_oft[addr];
        double temp_transition          = 0;
        int    same_ctr                 = 0;
        double transition_per_addr      = 0;
        double temp_linear_transition   = 0;
        double genuine_branch_entropy   = 0;

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
                transition_per_addr = double(m.second.n_transition) / double(m.second.n_execution); 
                transition_per_addr = 2 * std::min( transition_per_addr, (1 - transition_per_addr) ); 
                temp_linear_transition += transition_per_addr;
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
            branch_entropy += (ctr.n_taken + ctr.n_not_taken) * genuine_branch_entropy;
            // Accumulate the total number of conditional branch executions
            n_cbr_instructions += (ctr.n_taken + ctr.n_not_taken);
        }
    }

    // Normalize by the total number of conditional branch executions
    branch_entropy =  (branch_entropy / n_cbr_instructions);
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

