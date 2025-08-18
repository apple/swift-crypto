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
set -euo pipefail

log() { printf -- "** %s\n" "$*" >&2; }
error() { printf -- "** ERROR: %s\n" "$*" >&2; }
fatal() { error "$@"; exit 1; }
trap 'error "command failed (line ${LINENO})"' ERR

CURRENT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT=$(git -C "${CURRENT_SCRIPT_DIR}" rev-parse --show-toplevel)
DESTINATION_DIR=${REPO_ROOT}/Sources/CXKCP
VENDOR_LOGFILE="${DESTINATION_DIR}/vendored-sources.txt"

log "Checking required environment variables..."
test -n "${XKCP_PATH:-}" || fatal "XKCP_PATH unset"

log "Checking running from swift-crypto with no uncommited changes in destination dir: ${DESTINATION_DIR} ..."
PACKAGE_NAME=$(swift package --package-path "${REPO_ROOT}" describe --type text | /usr/bin/head -1 | grep "Name:" | awk '{ print $2 }')
if [[ "${PACKAGE_NAME}" != "swift-crypto" ]]; then
  fatal "Not running in swift-crypto; current package appears to be: ${PACKAGE_NAME}"
fi
[ -z "$(git -C "${REPO_ROOT}" status --porcelain -- "${DESTINATION_DIR}")" ] || fatal "Aborting vendor script: local changes detected."

log "Checking XKCP checkout exists: ${XKCP_PATH}"
test -d "${XKCP_PATH}/.git"

log "Getting XKCP hash..."
XKCP_DESCRIBE=$(git -C "${XKCP_PATH}" describe --all --long)
XKCP_BRANCH=$(git -C "${XKCP_PATH}" rev-parse --abbrev-ref HEAD)

# -----------------------------------------------------------------------------

log "Vendoring code from ${XKCP_PATH}#${XKCP_BRANCH} (${XKCP_DESCRIBE})"
XKCP_PACK_MAKE_TARGET=FIPS202-opt64.pack
XKCP_PACK_PATH="${XKCP_PATH}/bin/${XKCP_PACK_MAKE_TARGET/.pack/.tar.gz}"
make -C "${XKCP_PATH}" "${XKCP_PACK_MAKE_TARGET}"
tar -tf "${XKCP_PACK_PATH}" || fatal "Could not find expected built pack: ${XKCP_PACK_PATH}"

log "Unpacking to destination: ${DESTINATION_DIR}"
tar -C "${DESTINATION_DIR}" -xvf "${XKCP_PACK_PATH}"

cat > "${VENDOR_LOGFILE}" <<EOI
Vendored code from XKCP#${XKCP_BRANCH} (${XKCP_DESCRIBE}):
$(tar -tf "${XKCP_PACK_PATH}" | sed 's/^/- /')
EOI

# -----------------------------------------------------------------------------

COMMIT_MESSAGE="Revendor xkcp#${XKCP_BRANCH} (${XKCP_DESCRIBE})"
log "Committing vendored code."
git -C "${REPO_ROOT}" add "${DESTINATION_DIR}" "${VENDOR_LOGFILE}"
git -C "${REPO_ROOT}" commit -m "${COMMIT_MESSAGE}" --allow-empty

log "Vendor script complete!"
