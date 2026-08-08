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


#ifndef _BRANCH_ENTROPY_H_
#define _BRANCH_ENTROPY_H_ 

#include <unordered_map>
#include <stdint.h>
#include <cstdint>
// #include <mutex>

#include "drmemtrace/analysis_tool.h"
// #include "memref.h"
// #include "trace_entry.h"

namespace dynamorio {
namespace drmemtrace {

class branch_entropy_t : public analysis_tool_t {
public:
    branch_entropy_t();
    ~branch_entropy_t() override;

    bool process_memref(const memref_t &memref) override;
    bool print_results() override;

private:
    typedef struct _counter_per_branch_t {
        uint64_t n_taken = 0;
        uint64_t n_not_taken = 0;
    } counter_per_branch_t;

    uint32_t global_history = 0;
    uint64_t n_cbr_instructions = 0;
    double branch_entropy = 0;

    const uint64_t ADDR_MASK = ( (uint64_t) 1 << 10) - 1;
    const uint64_t HIST_MASK = ( (uint32_t) 1 << 10) - 1;

    std::unordered_map<addr_t, std::unordered_map<uint32_t, counter_per_branch_t>> global_oft;

};

} // namespace drmemtrace
} // namespace dynamorio

#endif /* _ENTROPY_H_ */
