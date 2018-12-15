#!/bin/sh

# Google perftools required

set -e
set -x

make clean profile

LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libprofiler.so CPUPROFILE=cpu_profile ./apathy $@

google-pprof --gv ./apathy ./cpu_profile
