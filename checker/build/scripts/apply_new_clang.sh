#!/bin/bash


script_dir=$(dirname $0)

clang_dir=$(cd "$(dirname "$0")/../Release+Asserts/bin/"; pwd)"/clang"

pushd $script_dir

echo "Executing sudo.."
sudo ../../llvm/tools/clang/tools/scan-build/set-xcode-analyzer --use-checker-build=$clang_dir

popd

