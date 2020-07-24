// swift-tools-version:5.1
//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
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

// This package contains a vendored copy of BoringSSL. For ease of tracking
// down problems with the copy of BoringSSL in use, we include a copy of the
// commit hash of the revision of BoringSSL included in the given release.
// This is also reproduced in a file called hash.txt in the
// Sources/CCryptoBoringSSL directory. The source repository is at
// https://boringssl.googlesource.com/boringssl.
//
// BoringSSL Commit: 54858b63c1d886f6c8d903d4a4f594f1485de189

import PackageDescription

let swiftSettings: [SwiftSetting] = [
    .define("CRYPTO_IN_SWIFTPM"),
    // To develop this on Apple platforms, uncomment this define.
    // .define("CRYPTO_IN_SWIFTPM_FORCE_BUILD_API"),
]

let package = Package(
    name: "swift-crypto",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .watchOS(.v6),
        .tvOS(.v13),
    ],
    products: [
        .library(name: "Crypto", targets: ["Crypto"]),
        /* This target is used only for symbol mangling. It's added and removed automatically because it emits build warnings. MANGLE_START
            .library(name: "CCryptoBoringSSL", type: .static, targets: ["CCryptoBoringSSL"]),
            MANGLE_END */
    ],
    dependencies: [],
    targets: [
        .target(name: "CCryptoBoringSSL"),
        .target(name: "CCryptoBoringSSLShims", dependencies: ["CCryptoBoringSSL"]),
        .target(name: "Crypto", dependencies: ["CCryptoBoringSSL", "CCryptoBoringSSLShims"], swiftSettings: swiftSettings),
        .target(name: "crypto-shasum", dependencies: ["Crypto"]),
        .testTarget(name: "CryptoTests", dependencies: ["Crypto"], swiftSettings: swiftSettings),
    ],
    cxxLanguageStandard: .cxx11
)
