#!/bin/bash

set -e

DIR=`pwd`
SCRIPT_DIR=$(dirname -- "$(readlink -f -- "$BASH_SOURCE")")
ROOT=$(cd ${SCRIPT_DIR}/.. && pwd)
#APK="${DIR}"/build-android/
#APK_ID=$(sed -En 's/^\s*\bapplicationId\s+"([^"]+)".*/\1/p' "${APP_ROOT}/build.gradle")

# https://developer.android.com/ndk/guides/abis.html
ABI=${ABI:-armeabi-v7a}
# Android API level
SDK_API=${SDK_API:-28}


if [ "$ABI" = "armeabi-v7a" ]; then
    NDK_ARCH="arm"
    NDK_TOOLCHAIN_TARGET="arm-linux-androideabi"
    NDK_TOOLCHAIN_LIB_SUBDIR="lib/armv7-a"
    CMAKE_SYSTEM_PROCESSOR="armv7-a"
    OPENSSL_MACHINE="armv7"
    CC_TARGET="armv7a"
    CC_SDK="eabi"$SDK_API

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
    CC_TARGET="i686"
    CC_SDK=$SDK_API

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
ANDROID_LIB_DIR=${ANDROID_LIB_DIR:-"$ROOT/../cross-compiled-libraries/android/lib/$ABI"}

# `posix_fadvise`, required by Boost.Beast is was only added in LOLLIPOP
# https://developer.android.com/guide/topics/manifest/uses-sdk-element.html#ApiLevels
NDK_PLATFORM=${NDK_PLATFORM:-28}

HOST_TAG=${HOST_TAG:-"linux-x86_64"}
#Autoconf projects allow you to specify the toolchain to use with environment variables.

#TODO hardcoded for ABI=arm eabi  need to be specifed
#export HOST_TAG=linux-x86_64
export TOOLCHAIN=$NDK_DIR/toolchains/llvm/prebuilt/$HOST_TAG


export AR=$TOOLCHAIN/bin/$NDK_TOOLCHAIN_TARGET-ar
export AS=$TOOLCHAIN/bin/$NDK_TOOLCHAIN_TARGET-as
export LD=$TOOLCHAIN/bin/$NDK_TOOLCHAIN_TARGET-ld
export RANLIB=$TOOLCHAIN/bin/$NDK_TOOLCHAIN_TARGET-ranlib
export SRTIP=$TOOLCHAIN/bin/$NDK_TOOLCHAIN_TARGET-strip

export CC=$TOOLCHAIN/bin/$CC_TARGET-linux-android$CC_SDK-clang
export CXX=$TOOLCHAIN/bin/$CC_TARGET-linux-android$CC_SDK-clang++

mkdir -p build-android-$ABI
cd build-android-$ABI

echo building with:
echo TOOLCHAIN=$NDK_DIR/toolchains/llvm/prebuilt/$HOST_TAG
echo AR=$TOOLCHAIN/bin/$NDK_TOOLCHAIN_TARGET-ar
echo AS=$TOOLCHAIN/bin/$NDK_TOOLCHAIN_TARGET-as
echo LD=$TOOLCHAIN/bin/$NDK_TOOLCHAIN_TARGET-ld
echo RANLIB=$TOOLCHAIN/bin/$NDK_TOOLCHAIN_TARGET-ranlib
echo SRTIP=$TOOLCHAIN/bin/$NDK_TOOLCHAIN_TARGET-strip

$ROOT/configure --without-boost --build=x86_64-unknown-linux-gnu --host=$NDK_TOOLCHAIN_TARGET CXXFLAGS="-I$ANDROID_INCLUDE_DIR -Wno-format-nonliteral -static" LDFLAGS="-L$ANDROID_LIB_DIR"
make VERBOSE=1

