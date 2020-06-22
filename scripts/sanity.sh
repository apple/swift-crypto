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

set -eu
here="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
function replace_acceptable_years() {
    # this needs to replace all acceptable forms with 'YEARS'
    sed -e 's/20[12][890]-20[12][90]/YEARS/' -e 's/2019/YEARS/' -e 's/2020/YEARS/'
}


# Run gyb, if generated files was changed -> fail
printf "=> Detecting manual edits in generated Swift files by comparing to gyb output\n"
FIRST_OUT="$(git status --porcelain)"
out=$($here/generate_boilerplate_files_with_gyb.sh 2>&1)
SECOND_OUT="$(git status --porcelain)"
if [ "$out" == *"error"* ]; then
  printf "\033[0;31merror!\033[0m\n"
  echo $out
  exit 1
fi
if [[ "$FIRST_OUT" != "$SECOND_OUT" ]]; then
  printf "\033[0;31mRunning gyb results in changes! Have you manually editted the generated swift files? Or did you forget to run gyb and commit changes?\033[0m\n"
  exit 1
fi
printf "\033[0;32mokay.\033[0m\n"


printf "=> Checking format\n"
FIRST_OUT="$(git status --porcelain)"
# only checking direcotry named BoringSSL, rest is shared code and we need to preserve original format
shopt -u dotglob
find Sources/* Tests/* -name BoringSSL -type d | while IFS= read -r d; do
  printf "   * checking $d... "
  out=$(swiftformat "$d" 2>&1)
  SECOND_OUT="$(git status --porcelain)"
  if [[ "$out" == *"error"*] && ["$out" != "*No eligible files" ]]; then
    printf "\033[0;31merror!\033[0m\n"
    echo $out
    exit 1
  fi
  if [[ "$FIRST_OUT" != "$SECOND_OUT" ]]; then
    printf "\033[0;31mformatting issues!\033[0m\n"
    git --no-pager diff
    exit 1
  fi
  printf "\033[0;32mokay.\033[0m\n"
done

printf "=> Checking #defines..."
if grep '\.define("CRYPTO_IN_SWIFTPM_FORCE_BUILD_API")' Package.swift | grep -v "//" > /dev/null; then
  printf "\033[0;31mstill in development mode!\033[0m Comment out CRYPTO_IN_SWIFTPM_FORCE_BUILD_API.\n"
  exit 1
else
  printf "\033[0;32mokay.\033[0m\n"
fi

printf "=> Checking license headers\n"
tmp=$(mktemp /tmp/.swift-crypto-sanity_XXXXXX)

for language in swift-or-c bash dtrace; do
  printf "   * $language... "
  declare -a matching_files
  declare -a exceptions
  expections=( )
  matching_files=( -name '*' )
  case "$language" in
      swift-or-c)
        exceptions=( -path '*Sources/CCryptoBoringSSL/*' -o -name 'Package.swift' )
        matching_files=( -name '*.swift' -o -name '*.c' -o -name '*.h' )
        cat > "$tmp" <<"EOF"
//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) YEARS Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
EOF
        ;;
      bash)
        matching_files=( -name '*.sh' )
        cat > "$tmp" <<"EOF"
#!/bin/bash
##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftCrypto open source project
##
## Copyright (c) YEARS Apple Inc. and the SwiftCrypto project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.md for the list of SwiftCrypto project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##
EOF
      ;;
      dtrace)
        matching_files=( -name '*.d' )
        cat > "$tmp" <<"EOF"
#!/usr/sbin/dtrace -q -s
/*===----------------------------------------------------------------------===*
 *
 *  This source file is part of the SwiftCrypto open source project
 *
 *  Copyright (c) YEARS Apple Inc. and the SwiftCrypto project authors
 *  Licensed under Apache License v2.0
 *
 *  See LICENSE.txt for license information
 *  See CONTRIBUTORS.md for the list of SwiftCrypto project authors
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *===----------------------------------------------------------------------===*/
EOF
      ;;
    *)
      echo >&2 "ERROR: unknown language '$language'"
      ;;
  esac

  expected_lines=$(cat "$tmp" | wc -l)
  expected_sha=$(cat "$tmp" | shasum)

  (
    cd "$here/.."
    find . \
      \( \! -path './.build/*' -a \
      \( "${matching_files[@]}" \) -a \
      \( \! \( "${exceptions[@]}" \) \) \) | while read line; do
      if [[ "$(cat "$line" | replace_acceptable_years | head -n $expected_lines | shasum)" != "$expected_sha" ]]; then
        printf "\033[0;31mmissing headers in file '$line'!\033[0m\n"
        diff -u <(cat "$line" | replace_acceptable_years | head -n $expected_lines) "$tmp"
        exit 1
      fi
    done
    printf "\033[0;32mokay.\033[0m\n"
  )
done

rm "$tmp"
