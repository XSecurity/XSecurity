#!/bin/bash

script_dir=$(dirname $0)

pushd $script_dir

sudo ../../llvm/tools/clang/tools/scan-build/set-xcode-analyzer --use-xcode-clang

popd

