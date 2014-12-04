#!/bin/bash

script_dir=$(dirname $0)

pushd $script_dir
echo "Executing sudo.."
sudo ../../llvm/tools/clang/tools/scan-build/set-xcode-analyzer --use-xcode-clang

popd

