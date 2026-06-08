//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
/// An elliptic curve that enables X25519 key agreement and Ed25519 signatures.
#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.13, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, visionOS 1.0, *)
#endif
public enum Curve25519: Sendable {}
#endif // Linux or !SwiftPM
