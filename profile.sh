#!/bin/sh

# Google perftools required

set -ex

make clean profile

LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libprofiler.so CPUPROFILE=cpu_profile ./apathy $@

google-pprof --gv ./apathy ./cpu_profile
