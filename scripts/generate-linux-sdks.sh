#!/bin/bash
##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftCrypto open source project
##
## Copyright (c) 2019-2025 Apple Inc. and the SwiftCrypto project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##
#
# This script generates Swift SDKs for Linux targets using the swift-sdk-generator.
# It should be run once before running the `vendor-boringssl.sh` script, which requires
# the Linux Swift SDKs to be installed.
#
# Usage:
#   1. Run this script to generate and install the Swift SDKs. This script can be re-run to
#      re-generate Swift SDKs if needed. Old SDKs will be removed before installing newly
#      generated ones.
#

set -e

SWIFT_VERSION=6.1.2
DISTRO_NAME=ubuntu
DISTRO_VERSION=noble
DISTRO_VERSION_GENERATOR=24.04
TMPDIR=$(mktemp -d /tmp/.workingXXXXXX)

function generate_swift_sdk {
    TARGET_ARCH=$1
    SDK_NAME="${SWIFT_VERSION}-RELEASE_${DISTRO_NAME}_${DISTRO_VERSION}_${TARGET_ARCH}"

    cd "$TMPDIR"
    if [ ! -d swift-sdk-generator ]; then
        echo "Cloning SDK generator..."
        git clone https://github.com/swiftlang/swift-sdk-generator.git
    fi

    cd swift-sdk-generator

    if [ "$TARGET_ARCH" = "armv7" ]; then
        DOWNLOAD_FILE=swift-${SWIFT_VERSION}-RELEASE-${DISTRO_NAME}-${DISTRO_VERSION}-armv7-install
        DOWNLOAD_PATH="${TMPDIR}/${DOWNLOAD_FILE}"
        echo "Downloading armv7 runtime..."
        wget -nc https://github.com/swift-embedded-linux/armhf-debian/releases/download/${SWIFT_VERSION}/${DOWNLOAD_FILE}.tar.gz && \
            echo "Extracting armv7 runtime..." && \
            mkdir "${DOWNLOAD_PATH}" && true && \
            tar -xf ${DOWNLOAD_FILE}.tar.gz -C "${DOWNLOAD_PATH}"

        echo "Creating Swift SDK for ${TARGET_ARCH}..."
        swift run swift-sdk-generator make-linux-sdk \
            --swift-version ${SWIFT_VERSION}-RELEASE \
            --distribution-name ${DISTRO_NAME} \
            --distribution-version ${DISTRO_VERSION_GENERATOR} \
            --target armv7-unknown-linux-gnueabihf \
            --target-swift-package-path "${DOWNLOAD_PATH}"
    else
        echo "Creating Swift SDK for ${TARGET_ARCH}..."
        swift run swift-sdk-generator make-linux-sdk \
            --swift-version ${SWIFT_VERSION}-RELEASE \
            --distribution-name ${DISTRO_NAME} \
            --distribution-version ${DISTRO_VERSION_GENERATOR} \
            --target "${TARGET_ARCH}-unknown-linux-gnu"
    fi

    swift sdk remove "${SDK_NAME}" || true  # ignore error if it doesn't exist
    swift sdk install "Bundles/${SDK_NAME}.artifactbundle"
}

echo "Generating Swift SDKs for Linux targets..."
generate_swift_sdk "x86_64"
generate_swift_sdk "aarch64"
generate_swift_sdk "armv7"
