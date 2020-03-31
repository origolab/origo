#!/bin/bash
echo "________Running test-linux.sh________"
set -e # fail on any error
set -u # treat unset variables as error

FEATURES="json-tests,ci-skip-tests"
OPTIONS="--release"
#use nproc `linux only
#THREADS=$(nproc)
THREADS=7

echo "________Running Parity Full Test Suite________"
time cargo test $OPTIONS --features "$FEATURES" --locked --jobs 4 --all -- --test-threads $THREADS
