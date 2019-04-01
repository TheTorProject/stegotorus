#!/bin/bash

SCRIPT_DIR=$(dirname -- "$(readlink -f -- "$BASH_SOURCE")")
ROOT=$(cd ${SCRIPT_DIR}/.. && pwd)

mkdir -p build-linux
cd build-linux

$ROOT/configure --build=x86_64-pc-linux-gnu --host=x86_64-pc-linux-gnu
make VERBOSE=1
