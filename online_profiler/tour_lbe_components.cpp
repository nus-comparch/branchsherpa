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
#define ADDRESS_LENGTH 7
// Number of history bits used for indexing the OFT
#define HISTORY_LENGTH 25

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


/* ******* Data structures and variables for the global history ******* */

// Global branch history and mask used to retain the most recent branch outcomes
#define GLOBAL_PATTERN uint32_t
#define GLOBAL_HISTORY_MASK (( 1u << HISTORY_LENGTH ) - 1 )
GLOBAL_PATTERN global_pattern = 0;

// OFT indexed by branch address and global history
#define GLOBAL_OFT_DATA_STRUCTURE std::unordered_map<app_pc, std::unordered_map<GLOBAL_PATTERN, counter_per_branch_t>> 
GLOBAL_OFT_DATA_STRUCTURE global_oft;

// Stores the branch entropy of each branch based on global history 
#define TOUR_PREDICTOR_GLOBAL std::unordered_map<app_pc, double>
TOUR_PREDICTOR_GLOBAL tour_predictor_entropy_global;


/* ******* Data structures and variables for local history ******* */

// Local branch history and mask used to retain the most recent branch outcomes
#define LOCAL_PATTERN uint32_t
#define LOCAL_HISTORY_MASK ( ( 1u << HISTORY_LENGTH ) - 1 )

// Stores the local history pattern for each branch instruction
#define PER_BRANCH_PATTERN std::unordered_map<app_pc, LOCAL_PATTERN> 
PER_BRANCH_PATTERN pattern_per_branch;

// OFT indexed by branch address and local history
#define LOCAL_OFT_DATA_STRUCTURE std::unordered_map<app_pc, std::unordered_map<LOCAL_PATTERN, counter_per_branch_t>> 
LOCAL_OFT_DATA_STRUCTURE local_oft;

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

    /* Record the branch outcome for both global and local history */
    
    // Record the history preceding the current branch
    GLOBAL_PATTERN global_history = global_pattern;

    /*
     *  Record the branch outcome under the current global history,
     *  then update the history with the observed outcome
     */
    auto &taken_update_global = global_oft[src];
    if (taken)
    {
        taken_update_global[global_history].n_taken++;
        global_pattern = (  ( global_history << 1 ) | 1 ) & GLOBAL_HISTORY_MASK;
    }
    else
    {
        taken_update_global[global_history].n_not_taken++;
        global_pattern = (  ( global_history << 1 ) | 0 ) & GLOBAL_HISTORY_MASK;
    }


    // Record the history preceding the current branch
    LOCAL_PATTERN local_history = pattern_per_branch[src];

    /*
     *  Record the branch outcome under the current local history,
     *  then update the history with the observed outcome
     */
    auto &taken_update_local = local_oft[src];
    if (taken)
    {
        taken_update_local[local_history].n_taken++;        
        pattern_per_branch[src] = (  ( local_history << 1 ) | 1 ) & LOCAL_HISTORY_MASK;
    }
    else
    {
        taken_update_local[local_history].n_not_taken++;        
        pattern_per_branch[src] = (  ( local_history << 1 ) | 0 ) & LOCAL_HISTORY_MASK;
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
            // Match global and local entropy values for the same branch address
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
    /*
     * Compute entropy for the global- and local-history
     *
     * Select the lower entropy between the global- and local-history
     * to obtain the tournament entropy for each branch 
     */    
    for (auto &g : global_oft) 
    {
        app_pc addr = g.first;

        // Compute entropy for each branch using global history
        double      tour_entropy_per_addr_global        = 0;
        uint64_t    total_instructions_per_addr_global  = 0;

        for (auto &a : g.second) 
        {
            GLOBAL_PATTERN hist = a.first;
            auto &ctr = a.second;

            double taken_probability = double(ctr.n_taken) / double(ctr.n_taken + ctr.n_not_taken);
            double linear_entropy = 2 * std::min(taken_probability, (1 - taken_probability));

            // Accumulate execution-weighted linear branch entropy
            tour_entropy_per_addr_global        += double(ctr.n_taken + ctr.n_not_taken) * linear_entropy;
            total_instructions_per_addr_global  += (ctr.n_taken + ctr.n_not_taken);
        }

        // Store the entropy of the global-history for each branch
        tour_predictor_entropy_global[addr] = (tour_entropy_per_addr_global / double(total_instructions_per_addr_global));
        // dr_printf("+++++++++++++++++ Global Tournament Entropy = %.6lf\n +++++++++++++++++", tour_predictor_entropy_global[addr]);
    }

    for (auto &l : local_oft) 
    {
        app_pc addr = l.first;

        // Compute entropy for each branch using local history
        double      tour_entropy_per_addr_local         = 0;
        uint64_t    total_instructions_per_addr_local   = 0;

        for (auto &b : l.second) {
            LOCAL_PATTERN hist = b.first;
            auto &ctr = b.second;

            double taken_probability = double(ctr.n_taken) / double(ctr.n_taken + ctr.n_not_taken);
            double linear_entropy = 2 * std::min(taken_probability, (1 - taken_probability));

            // Accumulate execution-weighted linear branch entropy
            tour_entropy_per_addr_local       += double(ctr.n_taken + ctr.n_not_taken) * linear_entropy;
            total_instructions_per_addr_local += (ctr.n_taken + ctr.n_not_taken);
        }

        // Store the entropy for the local-history for each branch
        tour_predictor_entropy_local[addr] = (tour_entropy_per_addr_local / double(total_instructions_per_addr_local));
        // dr_printf("+++++++++++++++++ Global Tournament Entropy = %.6lf\n +++++++++++++++++", tour_predictor_entropy_local[addr]);
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

