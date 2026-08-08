#!/bin/bash

set -e

# This script was written based on the instructions provided at:
# (https://dynamorio.org/page_building.html)

sudo apt-get install -y \
    cmake \
    g++ \
    g++-multilib \
    doxygen \
    git \
    zlib1g-dev \
    libunwind-dev \
    libsnappy-dev \
    liblz4-dev \
    libxxhash-dev

git clone --branch cronbuild-11.90.20203 --recurse-submodules -j4 https://github.com/DynamoRIO/dynamorio.git

cd dynamorio && mkdir build && cd build

cmake ..

make -j

gcc -O0 -o benchmarks/test_loop benchmarks/test_loop.c

./bin64/drrun echo "hello world"