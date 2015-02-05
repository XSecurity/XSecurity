#!/bin/bash

script_dir=$(dirname $0)

pushd $script_dir

#Setup sensitive information
mkdir ~/Applications/XSecurity
cp -rf ../../llvm/tools/clang/lib/StaticAnalyzer/Checkers/SensitiveInfo.txt ~/Applications/XSecurity/

#Use the pre-built clang binary
./apply_new_clang.sh

popd
