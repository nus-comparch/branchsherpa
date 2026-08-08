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


#include "branch_entropy.h"

#include <iostream>
#include <iomanip>
#include <cmath>
#include <algorithm>

using ::dynamorio::drmemtrace::analysis_tool_t;

namespace dynamorio {
namespace drmemtrace {

branch_entropy_t::branch_entropy_t()
    : global_history(0),
    n_cbr_instructions(0),
    branch_entropy(0)
{                               }

branch_entropy_t::~branch_entropy_t()
{                               }

bool branch_entropy_t::process_memref(const memref_t &memref) {
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

            addr_t masked_pc = memref.instr.addr & ADDR_MASK;
            uint32_t masked_hist = global_history & HIST_MASK;

            if(taken) {
                global_oft[masked_pc][masked_hist].n_taken++;
            }
            else {
                global_oft[masked_pc][masked_hist].n_not_taken++;
            }

            global_history = ((global_history << 1) | (taken ? 1 : 0)) & HIST_MASK;
            
        }    
    }
    return true;
}

bool branch_entropy_t::print_results() {
    n_cbr_instructions = 0;
    branch_entropy = 0;
    
    for(auto &p: global_oft) {
        addr_t addr = p.first;

        for(auto &a : p.second) {
            uint32_t hist = a.first;
            auto &ctr = a.second;

            double taken_probability = double(ctr.n_taken) / double(ctr.n_taken + ctr.n_not_taken);
            double linear_entropy = 2 * std::min( taken_probability, (1 - taken_probability));

            branch_entropy += (ctr.n_taken + ctr.n_not_taken) * linear_entropy;
            n_cbr_instructions += (ctr.n_taken + ctr.n_not_taken);
        }
    }

    branch_entropy = (branch_entropy / n_cbr_instructions);
    std::cout << "Total # of Instructions = " << n_cbr_instructions << std::endl;
    std::cout << "Branch Entropy = " << branch_entropy << std::endl;

    return true;
}


}   //namespace drmemtrace
}   // namespace dynamorio

extern "C" __attribute__((visibility("default")))
const char *get_tool_name() {
    return "branch_entropy";
}

extern "C" __attribute__((visibility("default")))
analysis_tool_t *analysis_tool_create() {
    return new dynamorio::drmemtrace::branch_entropy_t();
}