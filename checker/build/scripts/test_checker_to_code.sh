#!/bin/bash


if (( $# != 2 )); then
    echo "Usage: $0 <checker> <test file>" >&2
    echo "e.g. $0 osx.KeychainAPI test.m" >&2
    exit 1
fi

file_dir=$(dirname $2)
file_name=$(basename $2)
clang_dir=$(cd "$(dirname "$0")/../Release+Asserts/bin/"; pwd)"/clang"

pushd $file_dir

$clang_dir -cc1 -analyzer-checker=$1 $file_name

popd 



