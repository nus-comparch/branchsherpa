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
#include <vector>
#include <cmath>
#include <unordered_map>
#include <algorithm>

// Declare lock for preventing contention
static void *map_lock;

// Declare counters (i.e., "taken", "not taken", and "transitions") and a flag (i.e., p_outcome) for each conditional branch
typedef struct _counter_per_branch_t {
    uint64_t n_taken        = 0;
    uint64_t n_not_taken    = 0;
    uint64_t n_transition   = 0;
    int      p_outcome      = -1;
} counter_per_branch_t;

// Declare variables to compute taken rate, transition rate, and dynamic branches
typedef struct _class_info_t {
    double      taken_rate;
    double      transition_rate;
    uint64_t    n_execution;
} class_info_t;


// Declare a data structure for updating taken and transition count
#define CLASSIFICATION_DATA std::unordered_map<app_pc, counter_per_branch_t> 
CLASSIFICATION_DATA class_count;

// Declare a data structure for calculating 'taken rate' and 'transition rate'
#define CLASSIFICATION_RESULT std::unordered_map<app_pc, class_info_t> 
CLASSIFICATION_RESULT class_result;

// Distribution of static branches for taken rate, transition rate, and combination of both
std::vector<std::vector<uint64_t>> hybrid_class(20, std::vector<uint64_t>(20, 0));
std::vector<uint64_t> taken_class(20, 0);
std::vector<uint64_t> transition_class(20, 0);

// Distribution of dynamic branches for taken rate, transition rate, and combination of both
std::vector<std::vector<uint64_t>> hybrid_exec_class(20, std::vector<uint64_t>(20, 0));
std::vector<uint64_t> taken_exec_class(20, 0);
std::vector<uint64_t> transition_exec_class(20, 0);

// Declare a variable to count the entire branch executions
uint64_t n_cbr_instructions = 0;


static void
cbr_count(void *drcontext, app_pc src, app_pc targ, int taken)
{
    dr_mutex_lock(map_lock);

    if (taken)
    {
        if( class_count[src].p_outcome == -1 ) // Check whether it is the first access
        {
            /* 
             * Since it is the first access, 
             * increase the taken counter and raise the flag as "taken(= 1)""
             */
            class_count[src].n_taken++;
            class_count[src].p_outcome = 1;
        }
        else
        {
            /*
             * Since it is not the first access,
             * increase the taken counter and check the transition counter
             */
            class_count[src].n_taken++;
            if( class_count[src].p_outcome == 0 ) 
            {   class_count[src].n_transition++;    }

            class_count[src].p_outcome = 1;
        }
        
    }
    else
    {
        if( class_count[src].p_outcome == -1 )
        {
            class_count[src].n_not_taken++;
            class_count[src].p_outcome = 0;
        }
        else
        {
            class_count[src].n_not_taken++;
            if( class_count[src].p_outcome == 1 ) 
            {   class_count[src].n_transition++;    }

            class_count[src].p_outcome = 0;
        }
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
    // Calculate 'taken rate' and 'transition rate' of each branch and record the number of branch executions
    for (auto &c : class_count) 
    {
        uint64_t n_given_branch = 0;

        app_pc addr = c.first;
        n_given_branch = (c.second.n_taken + c.second.n_not_taken);

        class_result[addr].taken_rate = (static_cast<double>(c.second.n_taken) / n_given_branch); 
        class_result[addr].transition_rate = (static_cast<double>(c.second.n_transition) / n_given_branch);
        class_result[addr].n_execution = n_given_branch;
            
        n_cbr_instructions += n_given_branch;
    }

    int taken_num         = 0;
    int transition_num    = 0;

    // Classifying each branch instructions into each class of 'taken rate' and 'transition rate'
    for (auto &r : class_result)
    {
        int taken_num         = std::floor(r.second.taken_rate * 20);
        int transition_num    = std::floor(r.second.transition_rate * 20);

        taken_num         = std::min(19, std::max(0, taken_num));
        transition_num    = std::min(19, std::max(0, transition_num));

        // Counting number of times instructions belong to the class
        hybrid_class[transition_num][taken_num] += 1;
        taken_class[taken_num]                  += 1;
        transition_class[transition_num]        += 1;

        hybrid_exec_class[transition_num][taken_num]    += r.second.n_execution;
        taken_exec_class[taken_num]                     += r.second.n_execution;
        transition_exec_class[transition_num]           += r.second.n_execution;
    }

    dr_printf("===================== Distribution of conditional branches =====================\n\n");
    dr_printf("Considering Both\n\n");
    
    for (int n_tran = 0; n_tran < 20; ++n_tran) 
    {
        for (int n_tak = 0; n_tak < 20; ++n_tak) 
        {
            dr_printf("%" UINT64_FORMAT_CODE "\t", hybrid_class[n_tran][n_tak]);
        }

        dr_printf("\n\n");
    }

    dr_printf("Total # of the Executed Conditional Instructions: %" UINT64_FORMAT_CODE "\n\n", n_cbr_instructions);

    // Logging solely taken rate
    uint64_t n_taken_rate = 0;
    dr_printf("Taken Rate Distribution\n\n");
    for(int j = 0; j < 20; j++)
    {
        n_taken_rate += taken_class[j];
        dr_printf("%" UINT64_FORMAT_CODE "\t", taken_class[j]);
    }
    dr_printf("\nTotal # of Taken Rate Instructions = %" UINT64_FORMAT_CODE, n_taken_rate);

    // Logging solely transition rate
    uint64_t n_transition_rate = 0;
    dr_printf("\n\nTransition Rate Distribution\n\n");
    for (int z = 0; z < 20; z++)
    {
        n_transition_rate += transition_class[z];
        dr_printf("%" UINT64_FORMAT_CODE "\t", transition_class[z]);
    }
    dr_printf("\nTotal # of Transition Rate Instructions = %" UINT64_FORMAT_CODE "\n\n", n_transition_rate);

    
    dr_printf("===================== Distribution of Executions =====================\n\n");
    // Logging classification which considering both 'taken rate' and 'transition rate'
    dr_printf("Considering Both\n\n");
    
    uint64_t verify_executions = 0;
    for (int n_tran = 0; n_tran < 20; ++n_tran) 
    {
        for (int n_tak = 0; n_tak < 20; ++n_tak) 
        {
            // dr_printf("%u\t\t", n_tak);
            verify_executions += hybrid_exec_class[n_tran][n_tak];
            dr_printf("%" UINT64_FORMAT_CODE "\t", hybrid_exec_class[n_tran][n_tak]);
        }

        dr_printf("\n\n");
    }
    dr_printf("Total # of the Executed Conditional Instructions: %" UINT64_FORMAT_CODE "\n\n", verify_executions);


    // Logging solely taken rate
    dr_printf("Taken Rate Distribution\n\n");
    for(int j = 0; j < 20; j++)
    {
        dr_printf("%" UINT64_FORMAT_CODE "\t", taken_exec_class[j]);
    }

    // Logging solely transition rate
    dr_printf("\n\nTransition Rate Distribution\n\n");
    for (int z = 0; z < 20; z++)
    {
        dr_printf("%" UINT64_FORMAT_CODE "\t", transition_exec_class[z]);
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
