#!/bin/bash
##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftCrypto open source project
##
## Copyright (c) 2023 Apple Inc. and the SwiftCrypto project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.md for the list of SwiftCrypto project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

set -eu

sourcedir=$(dirname "$(readlink -f $0)")/..
workingdir=$(mktemp -d)
projectname=$(basename $workingdir)

cd $workingdir
swift package init

cat << EOF > Package.swift
// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "interop",
    platforms: [.macOS(.v10_15)],
    products: [
        .library(
            name: "interop",
            targets: ["interop"]
        ),
    ],
    dependencies: [
        .package(path: "$sourcedir")
    ],
    targets: [
        .target(
            name: "interop",
            // Depend on all products of swift-crypto to make sure they're all
            // compatible with cxx interop.
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto")
            ],
            swiftSettings: [.interoperabilityMode(.Cxx)]
        )
    ]
)
EOF

cat << EOF > Sources/$projectname/$(echo $projectname | tr . _).swift
import Crypto
import _CryptoExtras
EOF

swift build
