#!/bin/bash


if (( $# != 1 )); then
    echo "Usage: $0 <test source file> " >&2
    echo "e.g. $0 ../test/test.m" >&2
    exit 1
fi

script_dir=$(dirname $0)
source_path=$(cd $(dirname "$1") && pwd -P)/$(basename "$1")

echo Dumping AST of  $source_path

pushd $script_dir

../Release+Asserts/bin/clang -Xclang -ast-dump $source_path

popd


