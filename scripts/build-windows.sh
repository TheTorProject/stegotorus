#!/bin/bash

mkdir -p build-windows
cd build-windows

../../configure CXXFLAGS="-D__USE_MINGW_ANSI_STDIO=1 -Wno-format -Wno-unused-variable" --without-boost --build=x86_64-pc-linux-gnu --host=i686-w64-mingw32 
make
