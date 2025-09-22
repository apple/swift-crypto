// swift-tools-version:6.0
//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2023 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
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
// BoringSSL Commit: 0226f30467f540a3f62ef48d453f93927da199b6

import PackageDescription

import class Foundation.ProcessInfo

// To develop this on Apple platforms, set this to true
let development = false

// Ideally, we should use `.when(platforms:)` to set `swiftSettings` and
// `dependencies` like on other platforms. However, `Platform.freebsd` is not
// yet available, and therefore we guard the settings behind this boolean.
#if os(FreeBSD)
let isFreeBSD = true
#else
let isFreeBSD = false
#endif

let swiftSettings: [SwiftSetting]
let dependencies: [Target.Dependency]
if development || isFreeBSD {
    swiftSettings = [
        .define("CRYPTO_IN_SWIFTPM"),
        .define("CRYPTO_IN_SWIFTPM_FORCE_BUILD_API"),
    ]
    dependencies = [
        "CCryptoBoringSSL",
        "CCryptoBoringSSLShims",
        "CryptoBoringWrapper",
        "CXKCP",
        "CXKCPShims",
    ]
} else {
    let platforms: [Platform] = [
        Platform.linux,
        Platform.android,
        Platform.windows,
        Platform.wasi,
        Platform.openbsd,
    ]
    swiftSettings = [
        .define("CRYPTO_IN_SWIFTPM"),
        .define("CRYPTO_IN_SWIFTPM_FORCE_BUILD_API", .when(platforms: platforms)),
    ]
    dependencies = [
        .target(name: "CCryptoBoringSSL", condition: .when(platforms: platforms)),
        .target(name: "CCryptoBoringSSLShims", condition: .when(platforms: platforms)),
        .target(name: "CryptoBoringWrapper", condition: .when(platforms: platforms)),
        .target(name: "CXKCP", condition: .when(platforms: platforms)),
        .target(name: "CXKCPShims", condition: .when(platforms: platforms)),
    ]
}

// This doesn't work when cross-compiling: the privacy manifest will be included in the Bundle and
// Foundation will be linked. This is, however, strictly better than unconditionally adding the
// resource.
#if canImport(Darwin)
let privacyManifestExclude: [String] = []
let privacyManifestResource: [PackageDescription.Resource] = [.copy("PrivacyInfo.xcprivacy")]
#else
// Exclude on other platforms to avoid build warnings.
let privacyManifestExclude: [String] = ["PrivacyInfo.xcprivacy"]
let privacyManifestResource: [PackageDescription.Resource] = []
#endif

let package = Package(
    name: "swift-crypto",
    products: [
        .library(name: "Crypto", targets: ["Crypto"]),
        // Kept for backward compatibility
        .library(name: "_CryptoExtras", targets: ["_CryptoExtras"]),
        .library(name: "CryptoExtras", targets: ["CryptoExtras"]),
        /* This target is used only for symbol mangling. It's added and removed automatically because it emits build warnings. MANGLE_START
            .library(name: "CCryptoBoringSSL", type: .static, targets: ["CCryptoBoringSSL"]),
            MANGLE_END */
    ],
    dependencies: [
        // Dependencies are added below so that they can be switched between local and absolute URLs
    ],
    targets: [
        .target(
            name: "CCryptoBoringSSL",
            exclude: privacyManifestExclude + [
                "hash.txt",
                "CMakeLists.txt",
                /*
                 * These files are excluded to support WASI libc which doesn't provide <netdb.h>.
                 * This is safe for all platforms as we do not rely on networking features.
                 */
                "crypto/bio/connect.cc",
                "crypto/bio/socket_helper.cc",
                "crypto/bio/socket.cc",
            ],
            resources: privacyManifestResource,
            cSettings: [
                // These defines come from BoringSSL's build system
                .define("_HAS_EXCEPTIONS", to: "0", .when(platforms: [Platform.windows])),
                .define("WIN32_LEAN_AND_MEAN", .when(platforms: [Platform.windows])),
                .define("NOMINMAX", .when(platforms: [Platform.windows])),
                .define("_CRT_SECURE_NO_WARNINGS", .when(platforms: [Platform.windows])),
                /*
                 * These defines are required on Wasm/WASI, to disable use of pthread.
                 */
                .define(
                    "OPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED",
                    .when(platforms: [Platform.wasi])
                ),
                .define("OPENSSL_NO_ASM", .when(platforms: [Platform.wasi])),
            ]
        ),
        .target(
            name: "CXKCP",
            exclude: [
                "CMakeLists.txt"
            ],
            cSettings: [
                .define("XKCP_has_KeccakP1600"),
                .headerSearchPath("include"),
                .headerSearchPath("high"),
                .headerSearchPath("low"),
                .headerSearchPath("low/KeccakP-1600"),
                .headerSearchPath("low/common"),
                .headerSearchPath("common"),
            ]
        ),
        .target(
            name: "CCryptoBoringSSLShims",
            dependencies: ["CCryptoBoringSSL"],
            exclude: privacyManifestExclude + [
                "CMakeLists.txt"
            ],
            resources: privacyManifestResource
        ),
        .target(
            name: "CXKCPShims",
            dependencies: ["CXKCP"],
            exclude: privacyManifestExclude + [
                "CMakeLists.txt"
            ],
            resources: privacyManifestResource
        ),
        .target(
            name: "Crypto",
            dependencies: dependencies,
            exclude: privacyManifestExclude + [
                "CMakeLists.txt",
                "AEADs/Nonces.swift.gyb",
                "Digests/Digests.swift.gyb",
                "Key Agreement/ECDH.swift.gyb",
                "Signatures/ECDSA.swift.gyb",
                "Signatures/MLDSA.swift.gyb",
                "Signatures/BoringSSL/MLDSA_boring.swift.gyb",
                "KEM/MLKEM.swift.gyb",
                "KEM/BoringSSL/MLKEM_boring.swift.gyb",
            ],
            resources: privacyManifestResource,
            swiftSettings: swiftSettings
        ),
        .target(
            name: "CryptoExtras",
            dependencies: [
                "CCryptoBoringSSL",
                "CCryptoBoringSSLShims",
                "CryptoBoringWrapper",
                "Crypto",
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ],
            exclude: privacyManifestExclude + [
                "CMakeLists.txt"
            ],
            resources: privacyManifestResource,
            swiftSettings: swiftSettings
        ),
        .target(
            name: "_CryptoExtras",
            dependencies: [
                "CryptoExtras",
            ],
            swiftSettings: swiftSettings
        ),
        .target(
            name: "CryptoBoringWrapper",
            dependencies: [
                "CCryptoBoringSSL",
                "CCryptoBoringSSLShims",
            ],
            exclude: privacyManifestExclude + [
                "CMakeLists.txt"
            ],
            resources: privacyManifestResource
        ),
        .executableTarget(name: "crypto-shasum", dependencies: ["Crypto"]),
        .testTarget(
            name: "CryptoTests",
            dependencies: ["Crypto"],
            resources: [
                .copy("HPKE/hpke-test-vectors.json"),
                .copy("KEM/MLKEM768_BSSLKAT.json"),
                .copy("KEM/MLKEM768KAT.json"),
                .copy("KEM/MLKEM1024_BSSLKAT.json"),
                .copy("KEM/MLKEM1024KAT.json"),
                .copy("KEM/test-vectors.json"),
                .copy("Signatures/MLDSA/MLDSA65_KeyGen_KAT.json"),
                .copy("Signatures/MLDSA/MLDSA87_KeyGen_KAT.json"),
            ],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "CryptoExtrasTests",
            dependencies: ["CryptoExtras"],
            resources: [
                .copy("ECToolbox/H2CVectors/P256_XMD-SHA-256_SSWU_RO_.json"),
                .copy("ECToolbox/H2CVectors/P384_XMD-SHA-384_SSWU_RO_.json"),
                .copy("OPRFs/OPRFVectors/OPRFVectors-VOPRFDraft8.json"),
                .copy("OPRFs/OPRFVectors/OPRFVectors-VOPRFDraft19.json"),
                .copy("OPRFs/OPRFVectors/OPRFVectors-edgecases.json"),
            ],
            swiftSettings: swiftSettings
        ),
        .testTarget(name: "CryptoBoringWrapperTests", dependencies: ["CryptoBoringWrapper"]),
        .testTarget(name: "CXKCPTests", dependencies: ["CXKCP"]),
    ],
    cxxLanguageStandard: .cxx17
)

// Switch between local and remote dependencies depending on an environment variable
if ProcessInfo.processInfo.environment["SWIFTCI_USE_LOCAL_DEPS"] == nil {
    package.dependencies += [
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.2.0")
    ]
} else {
    package.dependencies += [
        .package(path: "../swift-asn1")
    ]
}

// ---    STANDARD CROSS-REPO SETTINGS DO NOT EDIT   --- //
for target in package.targets {
    switch target.type {
    case .regular, .test, .executable:
        var settings = target.swiftSettings ?? []
        // https://github.com/swiftlang/swift-evolution/blob/main/proposals/0444-member-import-visibility.md
        settings.append(.enableUpcomingFeature("MemberImportVisibility"))
        target.swiftSettings = settings
    case .macro, .plugin, .system, .binary:
        ()  // not applicable
    @unknown default:
        ()  // we don't know what to do here, do nothing
    }
}
// --- END: STANDARD CROSS-REPO SETTINGS DO NOT EDIT --- //
