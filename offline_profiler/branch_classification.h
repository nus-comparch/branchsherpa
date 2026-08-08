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


#ifndef _CLASSIFICATION_H_
#define _CLASSIFICATION_H_ 

#include <stdint.h>

#include <vector>
#include <unordered_map>
#include <stdint.h>
#include <cstdint>


#include "drmemtrace/analysis_tool.h"
// #include "memref.h"
// #include "trace_entry.h"

namespace dynamorio {
namespace drmemtrace {

class branch_classification_t : public analysis_tool_t {
public:
    branch_classification_t();
    ~branch_classification_t() override;

    bool process_memref(const memref_t &memref) override;

    bool print_results() override;

private:
    typedef struct _counter_per_branch_t {
        uint64_t n_taken        = 0;
        uint64_t n_not_taken    = 0;
        uint64_t n_transition   = 0;
        int      p_outcome      = -1;
    } counter_per_branch_t;

    typedef struct _class_info_t {
        double      taken_rate;
        double      transition_rate;
        uint64_t    n_execution;
    } class_info_t;

    std::unordered_map<addr_t, counter_per_branch_t> class_count;
    std::unordered_map<addr_t, class_info_t> class_result;

    uint64_t total_cbr_count = 0;
    // std::mutex map_lock;

    std::vector<std::vector<uint64_t>> hybrid_class;
    std::vector<uint64_t> taken_class;
    std::vector<uint64_t> transition_class;
    std::vector<std::vector<uint64_t>> hybrid_exec_class;
    std::vector<uint64_t> taken_exec_class;
    std::vector<uint64_t> transition_exec_class;

};

} // namespace drmemtrace
} // namespace dynamorio

#endif /* _SIMULATOR_H_ */
