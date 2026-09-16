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

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

#if canImport(CryptoKit)
@_exported import CryptoKit
#else
typealias SupportedCurveDetailsImpl = OpenSSLSupportedNISTCurve

protocol ECPublicKey {
    init <Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws(CryptoKitMetaError)
    var rawRepresentation: Data { get }
}

protocol ECPrivateKey {
    associatedtype PK
    var publicKey: PK { get }
}

protocol NISTECPublicKey: ECPublicKey {
    init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws(CryptoKitMetaError)
    init<Bytes: ContiguousBytes>(compressedRepresentation: Bytes) throws(CryptoKitMetaError)
    init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws(CryptoKitMetaError)
    
    var compactRepresentation: Data? { get }
    var x963Representation: Data { get }
}

protocol NISTECPrivateKey: ECPrivateKey where PK: NISTECPublicKey {
    init <Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws(CryptoKitMetaError)
    var rawRepresentation: Data { get }
}

/// An elliptic curve that enables NIST P-256 signatures and key agreement.
@nonexhaustive
public enum P256: Sendable { }

/// An elliptic curve that enables NIST P-384 signatures and key agreement.
@nonexhaustive
public enum P384: Sendable { }

/// An elliptic curve that enables NIST P-521 signatures and key agreement.
@nonexhaustive
public enum P521: Sendable { }
#endif // canImport(CryptoKit)
