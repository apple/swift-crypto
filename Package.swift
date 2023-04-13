// swift-tools-version:5.6
//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2023 Apple Inc. and the SwiftCrypto project authors
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
// BoringSSL Commit: abfd5ebc87ddca0fab9fca067c9d7edbc355eae8

import PackageDescription

// To develop this on Apple platforms, set this to true
let development = false

let swiftSettings: [SwiftSetting]
let dependencies: [Target.Dependency]
if development {
    swiftSettings = [
        .define("CRYPTO_IN_SWIFTPM"),
        .define("CRYPTO_IN_SWIFTPM_FORCE_BUILD_API"),
    ]
    dependencies = [
        "CCryptoBoringSSL",
        "CCryptoBoringSSLShims",
        "CryptoBoringWrapper"
    ]
} else {
    swiftSettings = [
        .define("CRYPTO_IN_SWIFTPM"),
    ]
    let platforms: [Platform] = [
        Platform.linux,
        Platform.android,
        Platform.windows,
        Platform.wasi,
    ]
    dependencies = [
        .target(name: "CCryptoBoringSSL", condition: .when(platforms: platforms)),
        .target(name: "CCryptoBoringSSLShims", condition: .when(platforms: platforms)),
        .target(name: "CryptoBoringWrapper", condition: .when(platforms: platforms))
    ]
}

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
        .library(name: "_CryptoExtras", targets: ["_CryptoExtras"]),
        /* This target is used only for symbol mangling. It's added and removed automatically because it emits build warnings. MANGLE_START
            .library(name: "CCryptoBoringSSL", type: .static, targets: ["CCryptoBoringSSL"]),
            MANGLE_END */
    ],
    dependencies: [],
    targets: [
        .target(
            name: "CCryptoBoringSSL",
            exclude: [
                "hash.txt",
                "include/boringssl_prefix_symbols_nasm.inc",
                "CMakeLists.txt",
                /*
                 * These files are excluded to support WASI libc which doesn't provide <netdb.h>.
                 * This is safe for all platforms as we do not rely on networking features.
                 */
                "crypto/bio/connect.c",
                "crypto/bio/socket_helper.c",
                "crypto/bio/socket.c"
            ],
            cSettings: [
                /*
                 * This define is required on Windows, but because we need older
                 * versions of SPM, we cannot conditionally define this on Windows
                 * only.  Unconditionally define it instead.
                 */
                .define("WIN32_LEAN_AND_MEAN"),
                /*
                 * These defines are required on Wasm/WASI, to disable use of pthread.
                 */
                .define("OPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED", .when(platforms: [Platform.wasi])),
                .define("OPENSSL_NO_ASM", .when(platforms: [Platform.wasi])),
            ]
        ),
        .target(
            name: "CCryptoBoringSSLShims",
            dependencies: ["CCryptoBoringSSL"],
            exclude: [
                "CMakeLists.txt"
            ]
        ),
        .target(
            name: "Crypto",
            dependencies: dependencies,
            exclude: [
                "CMakeLists.txt",
                "AEADs/Nonces.swift.gyb",
                "Digests/Digests.swift.gyb",
                "Key Agreement/ECDH.swift.gyb",
                "Signatures/ECDSA.swift.gyb",
            ],
            swiftSettings: swiftSettings
        ),
        .target(
            name: "_CryptoExtras",
            dependencies: [
                "CCryptoBoringSSL",
                "CCryptoBoringSSLShims",
                "CryptoBoringWrapper",
                "Crypto"
            ],
            exclude: [
                "CMakeLists.txt",
            ]
        ),
        .target(
            name: "CryptoBoringWrapper",
            dependencies: [
                "CCryptoBoringSSL",
                "CCryptoBoringSSLShims"
            ],
            exclude: [
                "CMakeLists.txt",
            ]
        ),
        .executableTarget(name: "crypto-shasum", dependencies: ["Crypto"]),
        .testTarget(name: "CryptoTests", dependencies: ["Crypto"], swiftSettings: swiftSettings),
        .testTarget(name: "_CryptoExtrasTests", dependencies: ["_CryptoExtras"]),
    ],
    cxxLanguageStandard: .cxx11
)
