#!/bin/bash
##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftCrypto open source project
##
## Copyright (c) 2021 Apple Inc. and the SwiftCrypto project authors
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

function update_cmakelists() {
    src_root="$here/Sources/$1"
    
    # Build an array with the rest of the arguments
    shift
    src_exts=("$@")
    echo "Finding source files (${src_exts[@]}) under $src_root"
    
    num_exts=${#src_exts[@]}
    
    # Build file extensions argument for `find`
    declare -a exts_arg
    exts_arg+=(-name "${src_exts[0]}")
    for (( i=1; i<$num_exts; i++ ));
    do
        exts_arg+=(-o -name "${src_exts[$i]}")
    done
    
    # Wrap quotes around each filename since it might contain spaces
    srcs=$($find "${src_root}" -type f \( "${exts_arg[@]}" \) -printf '  "%P"\n' | sort)
    echo "$srcs"
    
    # Update list of source files in CMakeLists.txt
    # The first part in `BEGIN` (i.e., `undef $/;`) is for working with multi-line;
    # the second is so that we can pass in a variable to replace with.
    perl -pi -e 'BEGIN { undef $/; $replace = shift } s/add_library\(([^\n]+)\n([^\)]+)/add_library\($1\n$replace/' "$srcs" "$src_root/CMakeLists.txt"
    echo "Updated $src_root/CMakeLists.txt"
}

update_cmakelists "CCryptoBoringSSL" "*.c"
update_cmakelists "CCryptoBoringSSLShims" "*.c"
update_cmakelists "Crypto" "*.swift"
