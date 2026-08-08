#!/bin/bash

# ***** Please modify below according to your environment *****

BENCH=(test_loop)

for b in "${BENCH[@]}"; do
    if [[ ! -f "${b}" ]]; then
        echo "Binary ${b} not found!" >&2
        continue
    fi

    "/path/to/dynamorio/build/bin64/drrun" \
    -c "/path/to/offline_profiler/build/libglobal_lbe_opt.so" \
    -- ${b}
done