#!/bin/bash
##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftCrypto open source project
##
## Copyright (c) 2019-2021 Apple Inc. and the SwiftCrypto project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
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

# BoringSSL revision can be passed as the first argument to this script.
if [ "$#" -gt 0 ]; then
    BORINGSSL_REVISION="$1"
fi

# This function namespaces the awkward inline functions declared in OpenSSL
# and BoringSSL.
function namespace_inlines {
    # Pull out all STACK_OF functions.
    STACKS=$(grep --no-filename -rE -e "DEFINE_(SPECIAL_)?STACK_OF\([A-Z_0-9a-z]+\)" -e "DEFINE_NAMED_STACK_OF\([A-Z_0-9a-z]+, +[A-Z_0-9a-z:]+\)" "$1/"* | grep -v '//' | grep -v '#' | gsed -e 's/DEFINE_\(SPECIAL_\)\?STACK_OF(\(.*\))/\2/' -e 's/DEFINE_NAMED_STACK_OF(\(.*\), .*)/\1/')
    STACK_FUNCTIONS=("call_free_func" "call_copy_func" "call_cmp_func" "new" "new_null" "num" "zero" "value" "set" "free" "pop_free" "insert" "delete" "delete_ptr" "find" "shift" "push" "pop" "dup" "sort" "is_sorted" "set_cmp_func" "deep_copy" "delete_if")

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

        # Begin by building for macOS. We build for two target triples, Intel
        # and Apple Silicon.
        swift build --triple "x86_64-apple-macosx" --product CCryptoBoringSSL
        swift build --triple "arm64-apple-macosx" --product CCryptoBoringSSL
        (
            cd "${SRCROOT}"
            go mod tidy -modcacherw
            go run "util/read_symbols.go" -out "${TMPDIR}/symbols-macOS-intel.txt" "${HERE}/.build/x86_64-apple-macosx/debug/libCCryptoBoringSSL.a"
            go run "util/read_symbols.go" -out "${TMPDIR}/symbols-macOS-as.txt" "${HERE}/.build/arm64-apple-macosx/debug/libCCryptoBoringSSL.a"
        )

        # Now build for iOS. We use xcodebuild for this because SwiftPM doesn't
        # meaningfully support it. Unfortunately we must archive ourselves.
        xcodebuild -sdk iphoneos -scheme CCryptoBoringSSL -derivedDataPath "${TMPDIR}/iphoneos-deriveddata" -destination generic/platform=iOS
        ar -r "${TMPDIR}/libCCryptoBoringSSL-ios.a" "${TMPDIR}/iphoneos-deriveddata/Build/Products/Debug-iphoneos/CCryptoBoringSSL.o"
        (
            cd "${SRCROOT}"
            go run "util/read_symbols.go" -out "${TMPDIR}/symbols-iOS.txt" "${TMPDIR}/libCCryptoBoringSSL-ios.a"
        )

        # Now cross compile for our targets.
        # NOTE: This requires running the `generate-linux-sdks.sh` script first to generate the Swift SDKs.
        swift build --swift-sdk 6.1.2-RELEASE_ubuntu_noble_x86_64 --product CCryptoBoringSSL
        swift build --swift-sdk 6.1.2-RELEASE_ubuntu_noble_aarch64 --product CCryptoBoringSSL
        swift build --swift-sdk 6.1.2-RELEASE_ubuntu_noble_armv7 --product CCryptoBoringSSL

        # Now we need to generate symbol mangles for Linux. We can do this in
        # one go for all of them.
        (
            cd "${SRCROOT}"
            go run "util/read_symbols.go" -obj-file-format elf -out "${TMPDIR}/symbols-linux-all.txt" "${HERE}"/.build/*-unknown-linux-*/debug/libCCryptoBoringSSL.a
        )

        # Now we concatenate all the symbols together and uniquify it. At this stage remove anything that
        # already has CCryptoBoringSSL in it, as those are namespaced by nature.
        cat "${TMPDIR}"/symbols-*.txt | sort | uniq | grep -v "CCryptoBoringSSL" > "${TMPDIR}/symbols.txt"

        # Use this as the input to the mangle.
        (
            cd "${SRCROOT}"
            go run "util/make_prefix_headers.go" -out "${HERE}/${DSTROOT}/include/openssl" "${TMPDIR}/symbols.txt"
        )

        # Remove the product, as we no longer need it.
        $sed -i -e 's/MANGLE_START\*\//MANGLE_START/' -e 's/\/\*MANGLE_END/MANGLE_END/' "${HERE}/Package.swift"
    )

    # Now remove any weird symbols that got in and would emit warnings.
    $sed -i -e '/#define .*\..*/d' "${DSTROOT}"/include/openssl/boringssl_prefix_symbols*.h

    # Now edit the headers again to add the symbol mangling.
    echo "ADDING symbol mangling"
    perl -pi -e '$_ .= qq(\n#define BORINGSSL_PREFIX CCryptoBoringSSL\n) if /#define OPENSSL_HEADER_BASE_H/' "$DSTROOT/include/openssl/base.h"

    # shellcheck disable=SC2044
    for assembly_file in $(find "$DSTROOT" -name "*.S")
    do
        $sed -i '1 i #define BORINGSSL_PREFIX CCryptoBoringSSL' "$assembly_file"
    done
    namespace_inlines "$DSTROOT"
}

function mangle_cpp_structures {
    echo "MANGLING C++ structures"
    (
        # We need a .a: may as well get SwiftPM to give it to us.
        # Temporarily enable the product we need.
        $sed -i -e 's/MANGLE_START/MANGLE_START*\//' -e 's/MANGLE_END/\/*MANGLE_END/' "${HERE}/Package.swift"

        # Build for macOS.
        swift build --product CCryptoBoringSSL

        # Woah, this is a hell of a command! What does it do?
        #
        # The nm command grabs all global defined symbols. We then run the C++ demangler over them and look for methods with '::' in them:
        # these are C++ methods. We then exclude any that contain CCryptoBoringSSL (as those are already namespaced!) and any that contain swift
        # (as those were put there by the Swift runtime, not us). This gives us a list of symbols. The following cut command
        # grabs the type name from each of those (the bit preceding the '::'). Then, we sort and uniqify that list.
        # Finally, we remove any symbol that ends in std. This gives us all the structures that need to be renamed.
        structures=$(nm -gUj "$(swift build --show-bin-path)/libCCryptoBoringSSL.a" | c++filt | grep "::" | grep -v -e "CCryptoBoringSSL" -e "swift" | cut -d : -f1 | grep -v "std$" | $sed -E -e 's/([^<>]*)(<[^<>]*>)?/\1/' | sort | uniq)

        for struct in ${structures}; do
            echo "#define ${struct} BORINGSSL_ADD_PREFIX(BORINGSSL_PREFIX, ${struct})" >> "${DSTROOT}/include/CCryptoBoringSSL_boringssl_prefix_symbols.h"
        done

        # Remove the product, as we no longer need it.
        $sed -i -e 's/MANGLE_START\*\//MANGLE_START/' -e 's/\/\*MANGLE_END/MANGLE_END/' "${HERE}/Package.swift"
    )
}

case "$(uname -s)" in
    Darwin)
        sed=gsed
        ;;
    *)
        # shellcheck disable=SC2209
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
rm -rf $DSTROOT/gen
rm -rf $DSTROOT/third_party

echo "CLONING boringssl"
mkdir -p "$SRCROOT"
git clone https://boringssl.googlesource.com/boringssl "$SRCROOT"
cd "$SRCROOT"
if [ "${BORINGSSL_REVISION:-}" ]; then
    echo "CHECKING OUT boringssl@${BORINGSSL_REVISION}"
    git checkout "$BORINGSSL_REVISION"
else
    BORINGSSL_REVISION=$(git rev-parse HEAD)
    echo "CLONED boringssl@${BORINGSSL_REVISION}"
fi
cd "$HERE"

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
    python3 "${HERE}/scripts/build-asm.py"
)

PATTERNS=(
'include/openssl/*.h'
'ssl/*.h'
'ssl/*.cc'
'crypto/*.h'
'crypto/*.cc'
'crypto/*/*.h'
'crypto/*/*.cc'
'crypto/*/*.S'
'crypto/*/*/*.h'
'crypto/*/*/*.cc.inc'
'crypto/*/*/*.inc'
'crypto/*/*/*.S'
'crypto/*/*/*/*.cc.inc'
'gen/crypto/*.cc'
'gen/crypto/*.S'
'gen/bcm/*.S'
'third_party/fiat/*.h'
'third_party/fiat/asm/*.S'
'third_party/fiat/*.c.inc'
)

EXCLUDES=(
'*_test.*'
'test_*.*'
'test'
'example_*.cc'
)

echo "COPYING boringssl"
for pattern in "${PATTERNS[@]}"
do
  for i in $SRCROOT/$pattern; do
    path=${i#"$SRCROOT"}
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

echo "REMOVING libssl"
(
    cd "$DSTROOT"
    rm "include/openssl/dtls1.h" "include/openssl/ssl.h" "include/openssl/srtp.h" "include/openssl/ssl3.h" "include/openssl/tls1.h"
    rm -rf "ssl"
)

echo "DISABLING assembly on x86 Windows"
(
    # x86 Windows builds require nasm for acceleration. SwiftPM can't do that right now,
    # so we disable the assembly.
    cd "$DSTROOT"
    $sed -i "/#define OPENSSL_HEADER_BASE_H/a#if defined(_WIN32) && (defined(__x86_64) || defined(_M_AMD64) || defined(_M_X64) || defined(__x86) || defined(__i386) || defined(__i386__) || defined(_M_IX86))\n#define OPENSSL_NO_ASM\n#endif" "include/openssl/base.h"

)

# Unfortunately, this patch for an upstream bug which incorrectly leaves C symbol using C++ mangling must be
# applied before we mangle symbols, so we can't place it with the others below.
echo "PATCHING BoringSSL (early)"
git apply "${HERE}/scripts/patch-3-missing-extern-c.patch"

mangle_symbols

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
    # shellcheck disable=SC2038
    find . -name "*.[ch]" -or -name "*.cc" -or -name "*.S" -or -name "*.c.inc" -or -name "*.cc.inc" | xargs $sed -i -e 's+include <openssl/\([[:alpha:]/]*/\)\{0,1\}+include <\1CCryptoBoringSSL_+' -e 's+include <boringssl_prefix_symbols+include <CCryptoBoringSSL_boringssl_prefix_symbols+' -e 's+include "openssl/\([[:alpha:]/]*/\)\{0,1\}+include "\1CCryptoBoringSSL_+'

    # Okay now we need to rename the headers adding the prefix "CCryptoBoringSSL_".
    pushd include
    while IFS= read -r -u3 -d $'\0' file; do
        dir=$(dirname "${file}")
        base=$(basename "${file}")
        mv "${file}" "${dir}/CCryptoBoringSSL_${base}"
    done 3< <(find . -name "*.h" -print0 | sort -rz)

    # Finally, make sure we refer to them by their prefixed names, and change any includes from angle brackets to quotation marks.
    # shellcheck disable=SC2038
    find . -name "*.h" | xargs $sed -i -e 's+include "\([[:alpha:]/]*/\)\{0,1\}+include "\1CCryptoBoringSSL_+' -e 's+include <\([[:alpha:]/]*/\)\{0,1\}CCryptoBoringSSL_\(.*\)>+include "\1CCryptoBoringSSL_\2"+'
    popd
)

echo "PATCHING BoringSSL"
git apply "${HERE}/scripts/patch-1-inttypes.patch"
git apply "${HERE}/scripts/patch-2-more-inttypes.patch"

# We need to avoid having the stack be executable. BoringSSL does this in its build system, but we can't.
echo "PROTECTING against executable stacks"
(
    cd "$DSTROOT"
    # shellcheck disable=SC2038
    find . -name "*.S" | xargs $sed -i '$ a #if defined(__linux__) && defined(__ELF__)\n.section .note.GNU-stack,"",%progbits\n#endif\n'
)

mangle_cpp_structures

# We need BoringSSL to be modularised
echo "MODULARISING BoringSSL"
cat << EOF > "$DSTROOT/include/CCryptoBoringSSL.h"
//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#ifndef C_CRYPTO_BORINGSSL_H
#define C_CRYPTO_BORINGSSL_H

#include "CCryptoBoringSSL_aead.h"
#include "CCryptoBoringSSL_aes.h"
#include "CCryptoBoringSSL_arm_arch.h"
#include "CCryptoBoringSSL_asn1_mac.h"
#include "CCryptoBoringSSL_asn1t.h"
#include "CCryptoBoringSSL_base.h"
#include "CCryptoBoringSSL_bio.h"
#include "CCryptoBoringSSL_blake2.h"
#include "CCryptoBoringSSL_blowfish.h"
#include "CCryptoBoringSSL_bn.h"
#include "CCryptoBoringSSL_boringssl_prefix_symbols.h"
#include "CCryptoBoringSSL_boringssl_prefix_symbols_asm.h"
#include "CCryptoBoringSSL_cast.h"
#include "CCryptoBoringSSL_chacha.h"
#include "CCryptoBoringSSL_cmac.h"
#include "CCryptoBoringSSL_conf.h"
#include "CCryptoBoringSSL_cpu.h"
#include "CCryptoBoringSSL_ctrdrbg.h"
#include "CCryptoBoringSSL_curve25519.h"
#include "CCryptoBoringSSL_des.h"
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
#include "CCryptoBoringSSL_mldsa.h"
#include "CCryptoBoringSSL_mlkem.h"
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
#include "CCryptoBoringSSL_xwing.h"

#endif  // C_CRYPTO_BORINGSSL_H
EOF

# modulemap is required by the cmake build
echo "CREATING modulemap"
cat << EOF > "$DSTROOT/include/module.modulemap"
module CCryptoBoringSSL {
    header "CCryptoBoringSSL.h"
    export *
}
EOF

echo "RECORDING BoringSSL revision"
$sed -i -e "s/BoringSSL Commit: [0-9a-f]\+/BoringSSL Commit: ${BORINGSSL_REVISION}/" "$HERE/Package.swift"
echo "This directory is derived from BoringSSL cloned from https://boringssl.googlesource.com/boringssl at revision ${BORINGSSL_REVISION}" > "$DSTROOT/hash.txt"

echo "CLEANING temporary directory"
rm -rf "${TMPDIR}"

