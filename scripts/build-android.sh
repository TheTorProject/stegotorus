#!/bin/bash

set -e

DIR=`pwd`
SCRIPT_DIR=$(dirname -- "$(readlink -f -- "$BASH_SOURCE")")
ROOT=$(cd ${SCRIPT_DIR}/.. && pwd)
#APK="${DIR}"/build-android/
#APK_ID=$(sed -En 's/^\s*\bapplicationId\s+"([^"]+)".*/\1/p' "${APP_ROOT}/build.gradle")

# https://developer.android.com/ndk/guides/abis.html
ABI=${ABI:-armeabi-v7a}

if [ "$ABI" = "armeabi-v7a" ]; then
    NDK_ARCH="arm"
    NDK_TOOLCHAIN_TARGET="arm-linux-androideabi"
    NDK_TOOLCHAIN_LIB_SUBDIR="lib/armv7-a"
    CMAKE_SYSTEM_PROCESSOR="armv7-a"
    OPENSSL_MACHINE="armv7"
elif [ "$ABI" = "arm64-v8a" ]; then
    NDK_ARCH="arm64"
    NDK_TOOLCHAIN_TARGET="aarch64-linux-android"
    CMAKE_SYSTEM_PROCESSOR="aarch64"
    OPENSSL_MACHINE="arm64"
elif [ "$ABI" = "armeabi" ]; then
    NDK_ARCH="arm"
    NDK_TOOLCHAIN_TARGET="arm-linux-androideabi"
    CMAKE_SYSTEM_PROCESSOR="armv5te"
    OPENSSL_MACHINE="armv4"
elif [ "$ABI" = "x86" ]; then
    NDK_ARCH="x86"
    NDK_TOOLCHAIN_TARGET="i686-linux-android"
    CMAKE_SYSTEM_PROCESSOR="i686"
    OPENSSL_MACHINE="i686"
elif [ "$ABI" = "x86_64" ]; then
    NDK_ARCH="x86_64"
    NDK_TOOLCHAIN_TARGET="x86_64-linux-android"
    NDK_TOOLCHAIN_LIB_SUBDIR="lib64"
    CMAKE_SYSTEM_PROCESSOR="x86_64"
    OPENSSL_MACHINE="x86_64"
else
    >&2 echo "TODO: Need a mapping from \"$ABI\" to other target selection variables"
    exit 1
fi

SDK_DIR=${SDK_DIR:-"/opt/android-sdk"}
NDK_DIR=${NDK_DIR:-"$SDK_DIR/ndk-bundle"}
ANDROID_INCLUDE_DIR=${ANDROID_LIB_DIR:-"$ROOT/../cross-compiled-libraries/android/include"}
ANDROID_LIB_DIR=${ANDROID_LIB_DIR:-"$ROOT/../cross-compiled-libraries/android/lib"}

# `posix_fadvise`, required by Boost.Beast is was only added in LOLLIPOP
# https://developer.android.com/guide/topics/manifest/uses-sdk-element.html#ApiLevels
NDK_PLATFORM=${NDK_PLATFORM:-28}

HOST_TAG=${HOST_TAG:-"linux-x86_64"}
#Autoconf projects allow you to specify the toolchain to use with environment variables.

#TODO hardcoded for ABI=arm eabi  need to be specifed
export HOST_TAG=linux-x86_64
export TOOLCHAIN=$NDK_DIR/toolchains/llvm/prebuilt/$HOST_TAG
export AR=$TOOLCHAIN/bin/arm-linux-androideabi-ar
export AS=$TOOLCHAIN/bin/arm-linux-androideabi-as
export CC=$TOOLCHAIN/bin/armv7a-linux-androideabi28-clang
export CXX=$TOOLCHAIN/bin/armv7a-linux-androideabi28-clang++
export LD=$TOOLCHAIN/bin/arm-linux-androideabi-ld
export RANLIB=$TOOLCHAIN/bin/arm-linux-androideabi-ranlib
export SRTIP=$TOOLCHAIN/bin/arm-linux-androideabi-strip

echo "NDK_DIR: "$NDK_DIR
echo "SDK_DIR: "$SDK_DIR
echo "NDK_TOOLCHAIN_DIR: "$NDK_TOOLCHAIN_DIR
echo "PLATFORM: "$PLATFORM

mkdir -p build-android
cd build-android

$ROOT/configure --without-boost --host=x86_64-unknown-linux-gnu --build=arm-linux-androideabi CXXFLAGS="-I$ANDROID_INCLUDE_DIR -Wno-format-nonliteral" LDFLAGS="-L$ANDROID_LIB_DIR"
make VERBOSE=1
