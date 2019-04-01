#!/bin/bash

SCRIPT_DIR=$(dirname -- "$(readlink -f -- "$BASH_SOURCE")")

$SCRIPT_DIR/build-linux.sh
$SCRIPT_DIR/build-windows.sh
$SCRIPT_DIR/build-android.sh
