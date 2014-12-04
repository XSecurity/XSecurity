#!/bin/bash


#if (( $# != 2 )); then
if [ $# -lt 2 ] || [ $# -gt 3 ]; then
    echo "Usage: $0 <checker> <app project path> [simulator version]" >&2
    echo ""
    echo "e.g. $0 msec.iosappsec.iOSAppSecInsecureNSUserDefaultsUsageChecker  ~\Project\testapp 6.1" >&2
    echo "Note: [simulator version] is optional the default is 6.0"
    echo ""
    exit 1
fi

if [ ! -d "$2" ]; then
   echo "$2 does not exist!"
   exit 1
fi

clang_dir=$(cd "$(dirname "$0")/../Release+Asserts/bin/"; pwd)"/clang"

scan_build_dir=$(cd "$(dirname "$0")/../../llvm/tools/clang/tools/scan-build/"; pwd)"/scan-build"

simulator_version="iphonesimulator6.0"


if (( $# > 2 )); then
    simulator_version="iphonesimulator"$3
fi

#go to the specified folder
pushd $2

#security.insecureAPI.getpw

real_cmd="$scan_build_dir --use-analyzer $clang_dir -enable-checker $1 xcodebuild -configuration Debug -sdk $simulator_version"
# real_cmd="$scan_build_dir --use-analyzer $clang_dir -enable-checker $1 -disable-checker security.insecureAPI.getpw xcodebuild -configuration Debug -sdk $simulator_version"

#real_cmd="$scan_build_dir --use-analyzer $clang_dir -disable-checker security.insecureAPI.getpw xcodebuild -configuration Debug -sdk $simulator_version"

#real_cmd="$scan_build_dir --use-analyzer $clang_dir -disable-checker security.insecureAPI.gets xcodebuild -configuration Debug -sdk $simulator_version"

#real_cmd="$scan_build_dir --use-analyzer $clang_dir -enable-checker $1 -disable-checker security.insecureAPI.gets xcodebuild -configuration Debug -sdk $simulator_version"
echo "######### scan_build_dir ########"
echo $scan_build_dir 
echo "######### scan_build_dir ########"
echo "."

echo "######### clang_dir ########"
echo $clang_dir 
echo "######### clang_dir ########"
echo "."

echo "######### real_cmd ########"
echo $real_cmd 
echo "######### real_cmd ########"
echo "."

$real_cmd

popd

