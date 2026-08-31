# MIT License
#
# Copyright (c) 2026 Dongin Lee and nus-comparch
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

cmake_minimum_required(VERSION 3.14)

project(OnlineProfiler)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

## ============= Building "branch classification tool" =============
add_library(classification SHARED classification.cpp)
configure_DynamoRIO_client(classification)
use_DynamoRIO_extension(classification drmgr)


## **************************** Linear Branch Entropy ****************************
## ============= Building "global entropy derivation tool (w/o optimizations)" =============
add_library(global_lbe_basic SHARED global_lbe_basic.cpp)
configure_DynamoRIO_client(global_lbe_basic)
use_DynamoRIO_extension(global_lbe_basic drmgr)

## ============= Building "global entropy derivation tool (w/ optimizations)" =============
add_library(global_lbe_opt SHARED global_lbe_opt.cpp)
configure_DynamoRIO_client(global_lbe_opt)
use_DynamoRIO_extension(global_lbe_opt drmgr)

## ============= Building "local entropy derivation tool (w/o optimizations)" =============
add_library(local_lbe_basic SHARED local_lbe_basic.cpp)
configure_DynamoRIO_client(local_lbe_basic)
use_DynamoRIO_extension(local_lbe_basic drmgr)

## ============= Building "local entropy derivation tool (w/ optimizations)" =============
add_library(local_lbe_opt SHARED local_lbe_opt.cpp)
configure_DynamoRIO_client(local_lbe_opt)
use_DynamoRIO_extension(local_lbe_opt drmgr)

## ============= Building "tour entropy derivation tool (w/o optimizations)" =============
add_library(tour_lbe_basic SHARED tour_lbe_basic.cpp)
configure_DynamoRIO_client(tour_lbe_basic)
use_DynamoRIO_extension(tour_lbe_basic drmgr)

## ============= Building "tour entropy derivation tool (w/ optimizations)" =============
add_library(tour_lbe_opt SHARED tour_lbe_opt.cpp)
configure_DynamoRIO_client(tour_lbe_opt)
use_DynamoRIO_extension(tour_lbe_opt drmgr)

## ============= Building "tour entropy derivation tool (for modeling multi-component predictors)" =============
add_library(tour_lbe_components SHARED tour_lbe_components.cpp)
configure_DynamoRIO_client(tour_lbe_components)
use_DynamoRIO_extension(tour_lbe_components drmgr)


## **************************** BranchSherpa ****************************
## ============= Building "global entropy derivation tool (for TAGE)" =============
add_library(global_longer_sherpa_tage SHARED global_longer_sherpa_tage.cpp)
configure_DynamoRIO_client(global_longer_sherpa_tage)
use_DynamoRIO_extension(global_longer_sherpa_tage drmgr)

## ============= Building "global entropy derivation tool (for TAGE using taken and transition rate)" =============
add_library(global_full_sherpa_tage SHARED global_full_sherpa_tage.cpp)
configure_DynamoRIO_client(global_full_sherpa_tage)
use_DynamoRIO_extension(global_full_sherpa_tage drmgr)

## ============= Building "local entropy derivation tool (for TAGE-SC-L)" =============
add_library(local_sherpa SHARED local_sherpa.cpp)
configure_DynamoRIO_client(local_sherpa)
use_DynamoRIO_extension(local_sherpa drmgr)

## ============= Building "tour entropy derivation tool (for TAGE-SC-L)" =============
add_library(tour_sherpa SHARED tour_sherpa.cpp)
configure_DynamoRIO_client(tour_sherpa)
use_DynamoRIO_extension(tour_sherpa drmgr)


