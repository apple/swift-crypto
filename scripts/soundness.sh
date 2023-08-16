#!/bin/bash
##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftCrypto open source project
##
## Copyright (c) 2019-2023 Apple Inc. and the SwiftCrypto project authors
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
    sed -e 's/20[12][8901]-20[12][90123]/YEARS/' -e 's/20[12][90123]/YEARS/'
}

printf "=> Checking for unacceptable language... "
# This greps for unacceptable terminology. The square bracket[s] are so that
# "git grep" doesn't find the lines that greps :).
# We exclude the vendored BoringSSL copy from this check.
unacceptable_terms=(
    -e blacklis[t]
    -e whitelis[t]
    -e slav[e]
    -e sanit[y]
)
if git grep --color=never -i "${unacceptable_terms[@]}" ':(exclude)Sources/CCryptoBoringSSL*' > /dev/null; then
    printf "\033[0;31mUnacceptable language found.\033[0m\n"
    git grep -i "${unacceptable_terms[@]}" ':(exclude)Sources/CCryptoBoringSSL*'
    exit 1
fi
printf "\033[0;32mokay.\033[0m\n"

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
  printf "\033[0;31mRunning gyb results in changes! Have you manually edited the generated Swift files? Or did you forget to run gyb and commit changes?\033[0m\n"
  exit 1
fi
printf "\033[0;32mokay.\033[0m\n"

printf "=> Detecting changes in source files for CMake build\n"
FIRST_OUT="$(git status --porcelain)"
out=$($here/update_cmakelists.sh 2>&1)
SECOND_OUT="$(git status --porcelain)"
if [[ "$FIRST_OUT" != "$SECOND_OUT" ]]; then
  printf "\033[0;31mThere are source file changes! Have you added or renamed source files? Or did you forget to run 'update_cmakelists.sh' and commit changes?\033[0m\n"
  exit 1
fi
printf "\033[0;32mokay.\033[0m\n"

printf "=> Checking format\n"
FIRST_OUT="$(git status --porcelain)"
# only checking directory named BoringSSL, rest is shared code and we need to preserve original format
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
if grep 'development = true' Package.swift > /dev/null; then
  printf "\033[0;31mstill in development mode!\033[0m Comment out CRYPTO_IN_SWIFTPM_FORCE_BUILD_API.\n"
  exit 1
else
  printf "\033[0;32mokay.\033[0m\n"
fi

printf "=> Checking license headers\n"
tmp=$(mktemp /tmp/.swift-crypto-soundness_XXXXXX)

for language in swift-or-c bash dtrace cmake; do
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
      cmake)
        matching_files=( -name 'SwiftSupport.cmake' -o -name 'CMakeLists.txt' )
        cat > "$tmp" <<"EOF"
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
