#!/bin/bash
##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftCrypto open source project
##
## Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

set -euo pipefail

log() { printf -- "** %s\n" "$*" >&2; }
error() { printf -- "** ERROR: %s\n" "$*" >&2; }
fatal() { error "$@"; exit 1; }

log "Checking if the cmake files are up-to-date..."

here="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
FIRST_OUT="$(git status --porcelain)"
_=$("$here"/update-cmake-lists.sh 2>&1)
SECOND_OUT="$(git status --porcelain)"
if [[ "$FIRST_OUT" != "$SECOND_OUT" ]]; then
  error "Changes in the cmake files detected. Please run the update-cmake-lists.sh script."
  exit 1
fi

log "✅ cmake files are up-to-date."
