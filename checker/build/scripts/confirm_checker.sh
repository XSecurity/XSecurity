#!/bin/bash


if (( $# != 1 )); then
    echo "Usage: $0 <checker> " >&2
    echo "e.g. $0 osx.KeychainAPI test.m" >&2
    exit 1
fi

script_dir=$(dirname $0)


pushd $script_dir

../Release+Asserts/bin/clang -cc1 -analyzer-checker-help | grep "$1"

popd


