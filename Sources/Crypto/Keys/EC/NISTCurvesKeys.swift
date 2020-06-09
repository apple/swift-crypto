//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import Foundation

#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
typealias SupportedCurveDetailsImpl = CorecryptoSupportedNISTCurve
#else
typealias SupportedCurveDetailsImpl = OpenSSLSupportedNISTCurve
#endif

protocol ECPublicKey {
    init <Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws
    var rawRepresentation: Data { get }
}

protocol ECPrivateKey {
    associatedtype PublicKey
    var publicKey: PublicKey { get }
}

protocol NISTECPublicKey: ECPublicKey {
    init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws
    init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws
    
    var compactRepresentation: Data? { get }
    var x963Representation: Data { get }
}

protocol NISTECPrivateKey: ECPrivateKey where PublicKey: NISTECPublicKey {
    init <Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws
    var rawRepresentation: Data { get }
}

/// The NIST P-256 Elliptic Curve.
public enum P256 { }

/// The NIST P-384 Elliptic Curve.
public enum P384 { }

/// The NIST P-521 Elliptic Curve.
public enum P521 { }
#endif // Linux or !SwiftPM
