#!/bin/bash
##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftCrypto open source project
##
## Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.md for the list of SwiftCrypto project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##
# This was substantially adapted from grpc-swift's vendor-boringssl.sh script.
# The license for the original work is reproduced below. See NOTICES.txt for
# more.
#
# Copyright 2016, gRPC Authors All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This script creates a vendored copy of BoringSSL that is
# suitable for building with the Swift Package Manager.
#
# Usage:
#   1. Run this script in the package root. It will place
#      a local copy of the BoringSSL sources in Sources/CCryptoBoringSSL.
#      Any prior contents of Sources/CCryptoBoringSSL will be deleted.
#
set -eou pipefail

HERE=$(pwd)
DSTROOT=Sources/CCryptoBoringSSL
TMPDIR=$(mktemp -d /tmp/.workingXXXXXX)
SRCROOT="${TMPDIR}/src/boringssl.googlesource.com/boringssl"
CROSS_COMPILE_TARGET_LOCATION="/Library/Developer/Destinations"
CROSS_COMPILE_VERSION="5.1.1"

# This function namespaces the awkward inline functions declared in OpenSSL
# and BoringSSL.
function namespace_inlines {
    # Pull out all STACK_OF functions.
    STACKS=$(grep --no-filename -rE -e "DEFINE_(SPECIAL_)?STACK_OF\([A-Z_0-9a-z]+\)" -e "DEFINE_NAMED_STACK_OF\([A-Z_0-9a-z]+, +[A-Z_0-9a-z:]+\)" "$1/"* | grep -v '//' | grep -v '#' | gsed -e 's/DEFINE_\(SPECIAL_\)\?STACK_OF(\(.*\))/\2/' -e 's/DEFINE_NAMED_STACK_OF(\(.*\), .*)/\1/')
    STACK_FUNCTIONS=("call_free_func" "call_copy_func" "call_cmp_func" "new" "new_null" "num" "zero" "value" "set" "free" "pop_free" "insert" "delete" "delete_ptr" "find" "shift" "push" "pop" "dup" "sort" "is_sorted" "set_cmp_func" "deep_copy")

    for s in $STACKS; do
        for f in "${STACK_FUNCTIONS[@]}"; do
            echo "#define sk_${s}_${f} BORINGSSL_ADD_PREFIX(BORINGSSL_PREFIX, sk_${s}_${f})" >> "$1/include/openssl/boringssl_prefix_symbols.h"
        done
    done

    # Now pull out all LHASH_OF functions.
    LHASHES=$(grep --no-filename -rE "DEFINE_LHASH_OF\([A-Z_0-9a-z]+\)" "$1/"* | grep -v '//' | grep -v '#' | grep -v '\\$' | gsed 's/DEFINE_LHASH_OF(\(.*\))/\1/')
    LHASH_FUNCTIONS=("call_cmp_func" "call_hash_func" "new" "free" "num_items" "retrieve" "call_cmp_key" "retrieve_key" "insert" "delete" "call_doall" "call_doall_arg" "doall" "doall_arg")

    for l in $LHASHES; do
        for f in "${LHASH_FUNCTIONS[@]}"; do
            echo "#define lh_${l}_${f} BORINGSSL_ADD_PREFIX(BORINGSSL_PREFIX, lh_${l}_${f})" >> "$1/include/openssl/boringssl_prefix_symbols.h"
        done
    done
}


# This function handles mangling the symbols in BoringSSL.
function mangle_symbols {
    echo "GENERATING mangled symbol list"
    (
        # We need a .a: may as well get SwiftPM to give it to us.
        # Temporarily enable the product we need.
        $sed -i -e 's/MANGLE_START/MANGLE_START*\//' -e 's/MANGLE_END/\/*MANGLE_END/' "${HERE}/Package.swift"

        export GOPATH="${TMPDIR}"

        # Begin by building for macOS.
        swift build --product CCryptoBoringSSL --enable-test-discovery
        go run "${SRCROOT}/util/read_symbols.go" -out "${TMPDIR}/symbols-macOS.txt" "${HERE}/.build/debug/libCCryptoBoringSSL.a"

        # Now build for iOS. We use xcodebuild for this because SwiftPM doesn't
        # meaningfully support it. Unfortunately we must archive ourselves.
        xcodebuild -sdk iphoneos -scheme CCryptoBoringSSL -derivedDataPath "${TMPDIR}/iphoneos-deriveddata"
        ar -r "${TMPDIR}/libCCryptoBoringSSL-ios.a" "${TMPDIR}/iphoneos-deriveddata/Build/Products/Debug-iphoneos/CCryptoBoringSSL.o"
        go run "${SRCROOT}/util/read_symbols.go" -out "${TMPDIR}/symbols-iOS.txt" "${TMPDIR}/libCCryptoBoringSSL-ios.a"

        # Now cross compile for our targets.
        # If you have trouble with the script around this point, consider
        # https://github.com/CSCIX65G/SwiftCrossCompilers to obtain cross
        # compilers for the architectures we care about.
        for cc_target in "${CROSS_COMPILE_TARGET_LOCATION}"/*"${CROSS_COMPILE_VERSION}"*.json; do
            echo "Cross compiling for ${cc_target}"
            swift build --product CCryptoBoringSSL --destination "${cc_target}" --enable-test-discovery
        done;

        # Now we need to generate symbol mangles for Linux. We can do this in
        # one go for all of them.
        go run "${SRCROOT}/util/read_symbols.go" -obj-file-format elf -out "${TMPDIR}/symbols-linux-all.txt" "${HERE}"/.build/*-unknown-linux/debug/libCCryptoBoringSSL.a

        # Now we concatenate all the symbols together and uniquify it.
        cat "${TMPDIR}"/symbols-*.txt | sort | uniq > "${TMPDIR}/symbols.txt"

        # Use this as the input to the mangle.
        go run "${SRCROOT}/util/make_prefix_headers.go" -out "${HERE}/${DSTROOT}/include/openssl" "${TMPDIR}/symbols.txt"

        # Remove the product, as we no longer need it.
        $sed -i -e 's/MANGLE_START\*\//MANGLE_START/' -e 's/\/\*MANGLE_END/MANGLE_END/' "${HERE}/Package.swift"
    )

    # Now remove any weird symbols that got in and would emit warnings.
    $sed -i -e '/#define .*\..*/d' "${DSTROOT}"/include/openssl/boringssl_prefix_symbols*.h

    # Now edit the headers again to add the symbol mangling.
    echo "ADDING symbol mangling"
    perl -pi -e '$_ .= qq(\n#define BORINGSSL_PREFIX CCryptoBoringSSL\n) if /#define OPENSSL_HEADER_BASE_H/' "$DSTROOT/include/openssl/base.h"

    for assembly_file in $(find "$DSTROOT" -name "*.S")
    do
        $sed -i '1 i #define BORINGSSL_PREFIX CCryptoBoringSSL' "$assembly_file"
    done
    namespace_inlines "$DSTROOT"
}

case "$(uname -s)" in
    Darwin)
        sed=gsed
        ;;
    *)
        sed=sed
        ;;
esac

if ! hash ${sed} 2>/dev/null; then
    echo "You need sed \"${sed}\" to run this script ..."
    echo
    echo "On macOS: brew install gnu-sed"
    exit 43
fi

echo "REMOVING any previously-vendored BoringSSL code"
rm -rf $DSTROOT/include
rm -rf $DSTROOT/ssl
rm -rf $DSTROOT/crypto
rm -rf $DSTROOT/third_party
rm -rf $DSTROOT/err_data.c

echo "CLONING boringssl"
mkdir -p "$SRCROOT"
git clone https://boringssl.googlesource.com/boringssl "$SRCROOT"
cd "$SRCROOT"
BORINGSSL_REVISION=$(git rev-parse HEAD)
cd "$HERE"
echo "CLONED boringssl@${BORINGSSL_REVISION}"

echo "OBTAINING submodules"
(
    cd "$SRCROOT"
    git submodule update --init
)

echo "GENERATING assembly helpers"
(
    cd "$SRCROOT"
    cd ..
    mkdir -p "${SRCROOT}/crypto/third_party/sike/asm"
    python "${HERE}/scripts/build-asm.py"
)

PATTERNS=(
'include/openssl/*.h'
'ssl/*.h'
'ssl/*.cc'
'crypto/*.h'
'crypto/*.c'
'crypto/*/*.h'
'crypto/*/*.c'
'crypto/*/*.S'
'crypto/*/*/*.h'
'crypto/*/*/*.c'
'crypto/*/*/*.S'
'crypto/*/*/*/*.c'
'third_party/fiat/*.h'
#'third_party/fiat/*.c'
)

EXCLUDES=(
'*_test.*'
'test_*.*'
'test'
'example_*.c'
)

echo "COPYING boringssl"
for pattern in "${PATTERNS[@]}"
do
  for i in $SRCROOT/$pattern; do
    path=${i#$SRCROOT}
    dest="$DSTROOT$path"
    dest_dir=$(dirname "$dest")
    mkdir -p "$dest_dir"
    cp "$SRCROOT/$path" "$dest"
  done
done

for exclude in "${EXCLUDES[@]}"
do
  echo "EXCLUDING $exclude"
  find $DSTROOT -d -name "$exclude" -exec rm -rf {} \;
done

echo "GENERATING err_data.c"
(
    cd "$SRCROOT/crypto/err"
    go run err_data_generate.go > "${HERE}/${DSTROOT}/crypto/err/err_data.c"
)

echo "DELETING crypto/fipsmodule/bcm.c"
rm -f $DSTROOT/crypto/fipsmodule/bcm.c

echo "FIXING missing include"
perl -pi -e '$_ .= qq(\n#include <openssl/cpu.h>\n) if /#include <openssl\/err.h>/' "$DSTROOT/crypto/fipsmodule/ec/p256-x86_64.c"

echo "REMOVING libssl"
(
    cd "$DSTROOT"
    rm "include/openssl/ssl.h" "include/openssl/srtp.h" "include/openssl/ssl3.h" "include/openssl/tls1.h"
    rm -rf "ssl"
)

mangle_symbols

# Removing ASM on 32 bit Apple platforms
echo "REMOVING assembly on 32-bit Apple platforms"
gsed -i "/#define OPENSSL_HEADER_BASE_H/a#if defined(__APPLE__) && defined(__i386__)\n#define OPENSSL_NO_ASM\n#endif" "$DSTROOT/include/openssl/base.h"

echo "RENAMING header files"
(
    # We need to rearrange a coouple of things here, the end state will be:
    # - Headers from 'include/openssl/' will be moved up a level to 'include/'
    # - Their names will be prefixed with 'CCryptoBoringSSL_'
    # - The headers prefixed with 'boringssl_prefix_symbols' will also be prefixed with 'CCryptoBoringSSL_'
    # - Any include of another header in the 'include/' directory will use quotation marks instead of angle brackets

    # Let's move the headers up a level first.
    cd "$DSTROOT"
    mv include/openssl/* include/
    rmdir "include/openssl"

    # Now change the imports from "<openssl/X> to "<CCryptoBoringSSL_X>", apply the same prefix to the 'boringssl_prefix_symbols' headers.
    find . -name "*.[ch]" -or -name "*.cc" -or -name "*.S" | xargs $sed -i -e 's+include <openssl/+include <CCryptoBoringSSL_+' -e 's+include <boringssl_prefix_symbols+include <CCryptoBoringSSL_boringssl_prefix_symbols+'

    # Okay now we need to rename the headers adding the prefix "CCryptoBoringSSL_".
    pushd include
    find . -name "*.h" | $sed -e "s_./__" | xargs -I {} mv {} CCryptoBoringSSL_{}
    # Finally, make sure we refer to them by their prefixed names, and change any includes from angle brackets to quotation marks.
    find . -name "*.h" | xargs $sed -i -e 's/include "/include "CCryptoBoringSSL_/' -e 's/include <CCryptoBoringSSL_\(.*\)>/include "CCryptoBoringSSL_\1"/'
    popd
)

# We need to avoid having the stack be executable. BoringSSL does this in its build system, but we can't.
echo "PROTECTING against executable stacks"
(
    cd "$DSTROOT"
    find . -name "*.S" | xargs $sed -i '$ a #if defined(__linux__) && defined(__ELF__)\n.section .note.GNU-stack,"",%progbits\n#endif\n'
)

echo "PATCHING BoringSSL"
git apply "${HERE}/scripts/patch-1-inttypes.patch"
git apply "${HERE}/scripts/patch-2-arm-arch.patch"

# We need BoringSSL to be modularised
echo "MODULARISING BoringSSL"
cat << EOF > "$DSTROOT/include/CCryptoBoringSSL.h"
//===----------------------------------------------------------------------===//
//
// This source file is part of the SwitCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#ifndef C_CRYPTO_BORINGSSL_H
#define C_CRYPTO_BORINGSSL_H

#include "CCryptoBoringSSL_aes.h"
#include "CCryptoBoringSSL_arm_arch.h"
#include "CCryptoBoringSSL_asn1_mac.h"
#include "CCryptoBoringSSL_asn1t.h"
#include "CCryptoBoringSSL_base.h"
#include "CCryptoBoringSSL_bio.h"
#include "CCryptoBoringSSL_blowfish.h"
#include "CCryptoBoringSSL_boringssl_prefix_symbols.h"
#include "CCryptoBoringSSL_boringssl_prefix_symbols_asm.h"
#include "CCryptoBoringSSL_cast.h"
#include "CCryptoBoringSSL_chacha.h"
#include "CCryptoBoringSSL_cmac.h"
#include "CCryptoBoringSSL_conf.h"
#include "CCryptoBoringSSL_cpu.h"
#include "CCryptoBoringSSL_curve25519.h"
#include "CCryptoBoringSSL_des.h"
#include "CCryptoBoringSSL_dtls1.h"
#include "CCryptoBoringSSL_e_os2.h"
#include "CCryptoBoringSSL_ec.h"
#include "CCryptoBoringSSL_ec_key.h"
#include "CCryptoBoringSSL_ecdsa.h"
#include "CCryptoBoringSSL_err.h"
#include "CCryptoBoringSSL_evp.h"
#include "CCryptoBoringSSL_hkdf.h"
#include "CCryptoBoringSSL_hmac.h"
#include "CCryptoBoringSSL_hrss.h"
#include "CCryptoBoringSSL_md4.h"
#include "CCryptoBoringSSL_md5.h"
#include "CCryptoBoringSSL_obj_mac.h"
#include "CCryptoBoringSSL_objects.h"
#include "CCryptoBoringSSL_opensslv.h"
#include "CCryptoBoringSSL_ossl_typ.h"
#include "CCryptoBoringSSL_pem.h"
#include "CCryptoBoringSSL_pkcs12.h"
#include "CCryptoBoringSSL_poly1305.h"
#include "CCryptoBoringSSL_rand.h"
#include "CCryptoBoringSSL_rc4.h"
#include "CCryptoBoringSSL_ripemd.h"
#include "CCryptoBoringSSL_rsa.h"
#include "CCryptoBoringSSL_safestack.h"
#include "CCryptoBoringSSL_sha.h"
#include "CCryptoBoringSSL_siphash.h"
#include "CCryptoBoringSSL_trust_token.h"
#include "CCryptoBoringSSL_x509v3.h"

#endif  // C_CRYPTO_BORINGSSL_H
EOF

echo "RECORDING BoringSSL revision"
$sed -i -e "s/BoringSSL Commit: [0-9a-f]\+/BoringSSL Commit: ${BORINGSSL_REVISION}/" "$HERE/Package.swift"
echo "This directory is derived from BoringSSL cloned from https://boringssl.googlesource.com/boringssl at revision ${BORINGSSL_REVISION}" > "$DSTROOT/hash.txt"

echo "CLEANING temporary directory"
rm -rf "${TMPDIR}"

