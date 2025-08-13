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
#   1. Run this script to generate Swift SDKs for Linux targets before running the
#      `vendor-boringssl.sh` script, which depends on them. This script can be re-run to 
#      re-generate Swift SDKs if needed- old SDKs will be removed before installing generated ones.
#

set -e

SWIFT_VERSION=5.10
TARGET_DISTRO=ubuntu-jammy
TMPDIR=$(mktemp -d /tmp/.workingXXXXXX)

function generate_swift_sdk {
    TARGET_ARCH=$1
    SDK_NAME="${SWIFT_VERSION}-RELEASE_${TARGET_DISTRO/-/_}_${TARGET_ARCH}"

    cd "$TMPDIR"
    if [ ! -d swift-sdk-generator ]; then
        echo "Cloning SDK generator..."
        git clone https://github.com/swiftlang/swift-sdk-generator.git
    fi

    cd swift-sdk-generator

    if [ "$TARGET_ARCH" = "armv7" ]; then
        DOWNLOAD_FILE=swift-${SWIFT_VERSION}-RELEASE-${TARGET_DISTRO}-armv7-install
        DOWNLOAD_PATH="${TMPDIR}/${DOWNLOAD_FILE}"
        echo "Downloading armv7 runtime..."
        wget -nc https://github.com/swift-embedded-linux/armhf-debian/releases/download/${SWIFT_VERSION}/${DOWNLOAD_FILE}.tar.gz && \
            echo "Extracting armv7 runtime..." && \
            mkdir "${DOWNLOAD_PATH}" && true && \
            tar -xf ${DOWNLOAD_FILE}.tar.gz -C "${DOWNLOAD_PATH}"

        echo "Creating Swift SDK for ${TARGET_ARCH}..."
        swift run swift-sdk-generator make-linux-sdk \
            --swift-version ${SWIFT_VERSION}-RELEASE \
            --distribution-name ubuntu \
            --distribution-version 22.04 \
            --target armv7-unknown-linux-gnueabihf \
            --target-swift-package-path "${DOWNLOAD_PATH}"
    else
        echo "Creating Swift SDK for ${TARGET_ARCH}..."
        swift run swift-sdk-generator make-linux-sdk \
            --swift-version ${SWIFT_VERSION}-RELEASE \
            --distribution-name ubuntu \
            --distribution-version 22.04 \
            --target ${TARGET_ARCH}-unknown-linux-gnu
    fi

    swift sdk remove "${SDK_NAME}" || true  # ignore error if it doesn't exist
    swift sdk install "Bundles/${SDK_NAME}.artifactbundle"
}

echo "Generating Swift SDKs for Linux targets..."
generate_swift_sdk "x86_64"
generate_swift_sdk "aarch64"
generate_swift_sdk "armv7"
