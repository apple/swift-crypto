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
#if CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
import SwiftSystem
#else
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
#endif

#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
#if (!CRYPTO_IN_SWIFTPM_FORCE_BUILD_API) || CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias SupportedCurveDetailsImpl = CorecryptoSupportedNISTCurve
#else
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias SupportedCurveDetailsImpl = OpenSSLSupportedNISTCurve
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
protocol ECPublicKey {
    init <Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws
    var rawRepresentation: Data { get }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
protocol ECPrivateKey {
    associatedtype PK
    var publicKey: PK { get }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
protocol NISTECPublicKey: ECPublicKey {
    init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws
    init<Bytes: ContiguousBytes>(compressedRepresentation: Bytes) throws
    init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws
    
    var compactRepresentation: Data? { get }
    var x963Representation: Data { get }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
protocol NISTECPrivateKey: ECPrivateKey where PK: NISTECPublicKey {
    init <Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws
    var rawRepresentation: Data { get }
}

/// An elliptic curve that enables NIST P-256 signatures and key agreement.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public enum P256: Sendable { }

/// An elliptic curve that enables NIST P-384 signatures and key agreement.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public enum P384: Sendable { }

/// An elliptic curve that enables NIST P-521 signatures and key agreement.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public enum P521: Sendable { }
#endif // Linux or !SwiftPM
