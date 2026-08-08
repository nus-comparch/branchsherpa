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

#define ADDRESS_LENGTH 2
#define HISTORY_LENGTH 10
// #define MINSERT instrlist_meta_preinsert

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

typedef struct _transition_info_t {
    int         p_outcome       = -1;
    uint64_t    n_transition    = 0;
    uint64_t    n_execution     = 0; 
} transition_info_t;


// Declare for Recording Local Pattern
#define LOCAL_PATTERN uint32_t
#define HISTORY_MASK ( ( ( uint32_t ) 1 << HISTORY_LENGTH ) - 1 )
// LOCAL_PATTERN global_pattern = 0;

// Declare "Outcome Frequency Table (OFT)" using Unodered Map (Hash Table) in C++
#define LOCAL_OFT_DATA_STRUCTURE std::unordered_map<app_pc, std::unordered_map<LOCAL_PATTERN, counter_per_branch_t>> 
LOCAL_OFT_DATA_STRUCTURE local_oft;

#define LOCAL_TRANSITION_DATA_STRUCTURE std::unordered_map<app_pc, transition_info_t>
LOCAL_TRANSITION_DATA_STRUCTURE local_transition_oft;

// Storing "Branch Pattern" for each branch instruction
#define PER_BRANCH_PATTERN std::unordered_map<app_pc, LOCAL_PATTERN> 
PER_BRANCH_PATTERN pattern_per_branch;

#define LOCAL_LINEAR_ENTROPY std::unordered_map<app_pc, std::unordered_map<LOCAL_PATTERN, entropy_info_t>>
LOCAL_LINEAR_ENTROPY local_linear_entropy_oft;

uint64_t n_cbr_instructions = 0;
double branch_entropy = 0;


static void
cbr_count(void *drcontext, app_pc src, app_pc targ, int taken)
{
    dr_mutex_lock(map_lock);

    uint64_t oft_address_mask = ( (uint64_t) 1 << ADDRESS_LENGTH ) - 1;
    uintptr_t masked_address = ((uintptr_t) src) & oft_address_mask;
    app_pc new_src = app_pc(masked_address);


    // Temporarily store local branch pattern per branch
    LOCAL_PATTERN history = pattern_per_branch[new_src];

    // Update the number of "not-taken" branches in the global OFT
    auto &taken_update = local_oft[new_src];
    auto &transition_update = local_transition_oft[src];

    if (taken)
    {
        // Update transition counter for taken case
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

        // Update the number of taken in "global OFT" and global branch pattern
        taken_update[history].n_taken++;
        pattern_per_branch[new_src] = (  ( history << 1 ) | 1 ) & HISTORY_MASK;
    }
    else
    {
        // Update transition counter for not-taken case
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

        // Update the number of not-taken in "global OFT" and global branch pattern
        taken_update[history].n_not_taken++;
        pattern_per_branch[new_src] = (  ( history << 1 ) | 0 ) & HISTORY_MASK;
    }
    dr_mutex_unlock(map_lock);
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data)
{
    // bool taken_or_not;
    app_pc src;

    // Instruemnt on conditional branch instructions
    if(!instr_is_cbr(instr))
        return DR_EMIT_DEFAULT;
    src = instr_get_app_pc(instr);

    // dr_mutex_lock(map_lock);
    // lookup(src);
    // dr_mutex_unlock(map_lock);                                                                                

    // Calculate both 'fallthrough' and 'target' address for further use
    app_pc fallthrough = (app_pc)decode_next_pc(drcontext, (byte *)src);
    app_pc target = instr_get_branch_target_pc(instr);
    
    dr_insert_cbr_instrumentation(drcontext, bb, instr, (void*)cbr_count);

    return DR_EMIT_DEFAULT;
}

void
dr_exit(void)
{
    dr_printf("======================== Branch Entropy Value for Address Length = 2 and History Length = 10 =======================\n\n");
    
    // Calculating taken rate, transition rate, and branch entropy of a specific address and history length of each conditional branch
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

        for(auto &m : local_transition_oft)
        {
            app_pc temp_addr = m.first;

            uint64_t address_mask = ( (uint64_t) 1 << ADDRESS_LENGTH ) - 1;
            uintptr_t temp_address = ((uintptr_t) temp_addr ) & address_mask;
            app_pc masked_src = app_pc(temp_address);

            if(masked_src == addr)
            {
                ++same_ctr; 
                transition_per_addr = double(m.second.n_transition) / double(m.second.n_execution); 
                transition_per_addr = 2 * std::min( transition_per_addr, (1 - transition_per_addr) ); 
                temp_linear_transition += transition_per_addr;
            }
        }
        temp_linear_transition = temp_linear_transition / same_ctr;

        for (auto &kv : p.second) 
        {
            LOCAL_PATTERN hist = kv.first;
            auto &ctr = kv.second;

            double temp_taken_rate = double(ctr.n_taken) / double(ctr.n_taken + ctr.n_not_taken);
            double temp_linear_entropy = 2 * std::min( temp_taken_rate, ( 1 - temp_taken_rate ) );  

            // dr_printf("****************** history ******************\n");
            // dr_printf("Taken Rate = %lf, Transition Rate = %lf\n", taken_update[hist].linear_entropy, transition_per_addr);
            genuine_branch_entropy = std::min(temp_linear_entropy, temp_linear_transition);

            // Calculating Final "Branch Entropy"
            branch_entropy += (ctr.n_taken + ctr.n_not_taken) * genuine_branch_entropy;
            n_cbr_instructions += (ctr.n_taken + ctr.n_not_taken);
        }
    }

    //Calculating Final "Branch Entropy"
    branch_entropy =  (branch_entropy / n_cbr_instructions);
    // dr_printf("Total Instruction # at = %u\n", n_cbr_instructions);
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

