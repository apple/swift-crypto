#!/bin/bash
##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftCrypto open source project
##
## Copyright (c) 2021-2023 Apple Inc. and the SwiftCrypto project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.md for the list of SwiftCrypto project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

set -eu

here=$(pwd)

case "$(uname -s)" in
    Darwin)
        find=gfind # brew install findutils
        ;;
    *)
        find=find
        ;;
esac

function update_cmakelists_source() {
    src_root="$here/Sources/$1"

    src_exts=("*.c" "*.swift")
    num_exts=${#src_exts[@]}
    echo "Finding source files (${src_exts[@]}) under $src_root"

    # Build file extensions argument for `find`
    declare -a exts_arg
    exts_arg+=(-name "${src_exts[0]}")
    for (( i=1; i<$num_exts; i++ ));
    do
        exts_arg+=(-o -name "${src_exts[$i]}")
    done
    
    # Build an array with the rest of the arguments
    shift
    exceptions=("$@")
    # Add path exceptions for `find`
    if (( ${#exceptions[@]} )); then
        echo "Excluding source paths (${exceptions[@]}) under $src_root"
        num_exceptions=${#exceptions[@]}
        for (( i=0; i<$num_exceptions; i++ ));
        do
            exts_arg+=(! -path "${exceptions[$i]}")
        done
    fi

    # Wrap quotes around each filename since it might contain spaces
    srcs=$($find "${src_root}" -type f \( "${exts_arg[@]}" \) -printf '  "%P"\n' | LC_ALL=POSIX sort)
    echo "$srcs"

    # Update list of source files in CMakeLists.txt
    # The first part in `BEGIN` (i.e., `undef $/;`) is for working with multi-line;
    # the second is so that we can pass in a variable to replace with.
    perl -pi -e 'BEGIN { undef $/; $replace = shift } s/add_library\(([^\n]+)\n([^\)]+)/add_library\($1\n$replace/' "$srcs" "$src_root/CMakeLists.txt"
    echo "Updated $src_root/CMakeLists.txt"
}

function update_cmakelists_assembly() {
    src_root="$here/Sources/$1"
    echo "Finding assembly files (.S) under $src_root"

    mac_x86_64_asms=$($find "${src_root}" -type f -name "*.mac.x86_64.S" -printf '    %P\n' | LC_ALL=POSIX sort)
    linux_x86_64_asms=$($find "${src_root}" -type f -name "*.linux.x86_64.S" -printf '    %P\n' | LC_ALL=POSIX sort)
    mac_aarch64_asms=$($find "${src_root}" -type f -name "*.ios.aarch64.S" -printf '    %P\n' | LC_ALL=POSIX sort)
    linux_aarch64_asms=$($find "${src_root}" -type f -name "*.linux.aarch64.S" -printf '    %P\n' | LC_ALL=POSIX sort)
    echo "$mac_x86_64_asms"
    echo "$linux_x86_64_asms"
    echo "$mac_aarch64_asms"
    echo "$linux_aarch64_asms"
    
    # Update list of assembly files in CMakeLists.txt
    # The first part in `BEGIN` (i.e., `undef $/;`) is for working with multi-line;
    # the second is so that we can pass in a variable to replace with.
    perl -pi -e 'BEGIN { undef $/; $replace = shift } s/Darwin([^\)]+)x86_64"\)\n  target_sources\(([^\n]+)\n([^\)]+)/Darwin$1x86_64"\)\n  target_sources\($2\n$replace/' "$mac_x86_64_asms" "$src_root/CMakeLists.txt"
    perl -pi -e 'BEGIN { undef $/; $replace = shift } s/Linux([^\)]+)x86_64"\)\n  target_sources\(([^\n]+)\n([^\)]+)/Linux$1x86_64"\)\n  target_sources\($2\n$replace/' "$linux_x86_64_asms" "$src_root/CMakeLists.txt"
    perl -pi -e 'BEGIN { undef $/; $replace = shift } s/Darwin([^\)]+)aarch64"\)\n  target_sources\(([^\n]+)\n([^\)]+)/Darwin$1aarch64"\)\n  target_sources\($2\n$replace/' "$mac_aarch64_asms" "$src_root/CMakeLists.txt"
    perl -pi -e 'BEGIN { undef $/; $replace = shift } s/Linux([^\)]+)aarch64"\)\n  target_sources\(([^\n]+)\n([^\)]+)/Linux$1aarch64"\)\n  target_sources\($2\n$replace/' "$linux_aarch64_asms" "$src_root/CMakeLists.txt"
    echo "Updated $src_root/CMakeLists.txt"
}

update_cmakelists_source "CCryptoBoringSSL"
update_cmakelists_source "CCryptoBoringSSLShims"
update_cmakelists_source "CryptoBoringWrapper"
update_cmakelists_source "Crypto"
update_cmakelists_source "_CryptoExtras" "*/AES/*.swift"

update_cmakelists_assembly "CCryptoBoringSSL"
