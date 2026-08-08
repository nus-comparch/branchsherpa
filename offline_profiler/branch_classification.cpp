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


#include "branch_classification.h"

#include <iostream>
#include <iomanip>
#include <cmath>
#include <algorithm>
#include <mutex>

uint64_t n_cbr_instruction = 0;
using ::dynamorio::drmemtrace::analysis_tool_t;

namespace dynamorio {
namespace drmemtrace {

branch_classification_t::branch_classification_t()
    :   hybrid_class(20, std::vector<uint64_t>(20, 0)),
        taken_class(20, 0),
        transition_class(20, 0),
        hybrid_exec_class(20, std::vector<uint64_t>(20, 0)),
        taken_exec_class(20, 0),
        transition_exec_class(20, 0)
{                               }

branch_classification_t::~branch_classification_t()
{                               }

bool branch_classification_t::process_memref(const memref_t &memref) {
    if(type_is_instr(memref.instr.type)) {
        if(type_is_instr_conditional_branch(memref.instr.type)) {
            bool taken = false;

            if(memref.instr.type == TRACE_TYPE_INSTR_TAKEN_JUMP) {
                taken = true;
            }
            else if(memref.instr.type == TRACE_TYPE_INSTR_UNTAKEN_JUMP) {
                taken = false;
            }
            else {
                // std::cout << "Not a Target CBR!!\n\n";
                return true;
            }

            // std::lock_guard<std::mutex> guard(map_lock);

            addr_t pc = memref.instr.addr;
            auto &counter = class_count[pc];

            if(taken) {
                if(counter.p_outcome == -1) {
                    counter.n_taken++;
                    counter.p_outcome = 1;
                }
                else {
                    counter.n_taken++;
                    if(counter.p_outcome == 0)
                    {   counter.n_transition++; }
                    counter.p_outcome = 1;
                }

            }
            else {
                if(counter.p_outcome == -1) {
                    counter.n_not_taken++;
                    counter.p_outcome = 0;
                }
                else {
                    counter.n_not_taken++;
                    if(counter.p_outcome == 1)
                    {   counter.n_transition++; }
                    counter.p_outcome = 0;
                }
            }

            total_cbr_count++;
        }    
    }

    return true;
}

bool branch_classification_t::print_results() {
    uint64_t n_given_branch = 0;

    for(auto &c : class_count)
    {
        n_given_branch = 0;

        addr_t addr = c.first;
        n_given_branch = (class_count[addr].n_taken + class_count[addr].n_not_taken);

        class_result[addr].taken_rate = (static_cast<double>(class_count[addr].n_taken) / n_given_branch);
        class_result[addr].transition_rate = (static_cast<double>(class_count[addr].n_transition) / n_given_branch);
        class_result[addr].n_execution = n_given_branch;

        n_cbr_instruction += n_given_branch;
    }

    int taken_num       = 0;
    int transition_num  = 0;

    for(auto &r : class_result)
    {
        taken_num       = std::floor(r.second.taken_rate * 20);
        transition_num  = std::floor(r.second.transition_rate * 20);

        taken_num = std::min(19, std::max(0, taken_num));
        transition_num = std::min(19, std::max(0, transition_num));

        hybrid_class[transition_num][taken_num] += 1;
        taken_class[taken_num]                  += 1;
        transition_class[transition_num]        += 1;

        hybrid_exec_class[transition_num][taken_num]    += r.second.n_execution;
        taken_exec_class[taken_num]                     += r.second.n_execution;
        transition_exec_class[transition_num]           += r.second.n_execution;
    }

    std::cout << "===================== Distribution of Instructions =====================\n\n";
    std::cout << "Considering Both\n\n";

    for (int n_tran = 0; n_tran < 20; ++n_tran) 
    {
        for (int n_tak = 0; n_tak < 20; ++n_tak) 
        {
            std::cout << hybrid_class[n_tran][n_tak] << "\t";
        }
        std::cout << "\n\n";
    }

    std::cout << "Total # of the Executed Conditional Instructions: " << n_cbr_instruction << "\n\n";

    uint64_t n_taken_rate = 0;
    std::cout << "Taken Rate Distribution\n\n";
    for(int j = 0; j < 20; j++)
    {
        n_taken_rate += taken_class[j];
        std::cout << taken_class[j] << "\t";
    }
    std::cout << "\nTotal # of Taken Rate Instructions = " << n_taken_rate;
    // std::cout << "\n\n"

    uint64_t n_transition_rate = 0;
    std::cout << "\n\nTransition Rate Distribution\n\n";

    for (int z = 0; z < 20; z++)
    {
        n_transition_rate += transition_class[z];
        std::cout << transition_class[z] << "\t";
    }
    std::cout << "\nTotal # of Transition Rate Instructions = " << n_transition_rate;
    std::cout << "\n\n";

    std::cout << "===================== Distribution of Executions =====================\n\n";
    std::cout << "Considering Both\n\n";

    uint64_t verify_executions = 0;
    for (int n_tran = 0; n_tran < 20; ++n_tran) 
    {
        for (int n_tak = 0; n_tak < 20; ++n_tak) 
        {
            // dr_printf("%u\t\t", n_tak);
            verify_executions += hybrid_exec_class[n_tran][n_tak];
            std::cout << hybrid_exec_class[n_tran][n_tak] << "\t";
        }

        std::cout << "\n\n";
    }
    std::cout << "Total # of the Executed Conditional Instructions: " << verify_executions;
    std::cout << "\n\n";

    std::cout << "Taken Rate Distribution\n\n";

    for(int j = 0; j < 20; j++)
    {
        std::cout << taken_exec_class[j] << "\t";
    }

    // Logging solely transition rate
    std::cout << "\n\nTransition Rate Distribution\n\n";
    for (int z = 0; z < 20; z++)
    {
        std::cout << transition_exec_class[z] << "\t";
    }

    std::cout << std::endl;

    return true;
}


}   //namespace drmemtrace
}   // namespace dynamorio

extern "C" __attribute__((visibility("default")))
const char *get_tool_name() {
    return "branch_classification";
}

extern "C" __attribute__((visibility("default")))
analysis_tool_t *analysis_tool_create() {
    return new dynamorio::drmemtrace::branch_classification_t();
}