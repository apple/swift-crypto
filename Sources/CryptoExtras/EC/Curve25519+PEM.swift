//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import SwiftASN1

@available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
extension Curve25519.Signing.PrivateKey {
    /// A Privacy-Enhanced Mail (PEM) representation of the private key.
    public var pemRepresentation: String {
        ASN1.PEMDocument(type: "PRIVATE KEY", derBytes: self.pkcs8DERRepresentation).pemString
    }

    /// Creates a Curve25519 private key for signing from a Privacy-Enhanced Mail
    /// (PEM) representation.
    ///
    /// - Parameters:
    ///   - pemRepresentation: A PEM representation of the key.
    public init(pemRepresentation: String) throws {
        let document = try PEMDocument(pemString: pemRepresentation)
        let pkcs8Key = try ASN1.PKCS8PrivateKey(derEncoded: document.derBytes)
        self = try .init(rawRepresentation: pkcs8Key.privateKey.bytes)
    }
}

@available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
extension Curve25519.Signing.PublicKey {
    /// A Privacy-Enhanced Mail (PEM) representation of the public key.
    public var pemRepresentation: String {
        let spki = SubjectPublicKeyInfo(
            algorithmIdentifier: .init(algorithm: .AlgorithmIdentifier.idEd25519, parameters: nil),
            key: Array(self.rawRepresentation)
        )

        var serializer = DER.Serializer()
        try! serializer.serialize(spki)

        return PEMDocument(type: "PUBLIC KEY", derBytes: serializer.serializedBytes).pemString
    }

    /// Creates a Curve25519 public key for signing from a Privacy-Enhanced Mail
    /// (PEM) representation.
    ///
    /// - Parameters:
    ///   - pemRepresentation: A PEM representation of the key.
    public init(pemRepresentation: String) throws {
        let document = try PEMDocument(pemString: pemRepresentation)
        let spki = try SubjectPublicKeyInfo(derEncoded: document.derBytes)
        guard spki.algorithmIdentifier.algorithm == .AlgorithmIdentifier.idEd25519 else {
            throw CryptoKitASN1Error.invalidPEMDocument
        }
        self = try .init(rawRepresentation: spki.key.bytes)
    }
}

@available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
extension Curve25519.KeyAgreement.PrivateKey {
    /// A Privacy-Enhanced Mail (PEM) representation of the private key.
    public var pemRepresentation: String {
        ASN1.PEMDocument(type: "PRIVATE KEY", derBytes: self.pkcs8DERRepresentation).pemString
    }

    /// Creates a Curve25519 private key for key agreement from a Privacy-Enhanced Mail
    /// (PEM) representation.
    ///
    /// - Parameters:
    ///   - pemRepresentation: A PEM representation of the key.
    public init(pemRepresentation: String) throws {
        let document = try PEMDocument(pemString: pemRepresentation)
        let pkcs8Key = try ASN1.PKCS8PrivateKey(derEncoded: document.derBytes)
        self = try .init(rawRepresentation: pkcs8Key.privateKey.bytes)
    }
}

@available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
extension Curve25519.KeyAgreement.PublicKey {
    /// A Privacy-Enhanced Mail (PEM) representation of the public key.
    public var pemRepresentation: String {
        let spki = SubjectPublicKeyInfo(
            algorithmIdentifier: .init(algorithm: .AlgorithmIdentifier.idX25519, parameters: nil),
            key: Array(self.rawRepresentation)
        )

        var serializer = DER.Serializer()
        try! serializer.serialize(spki)

        return PEMDocument(type: "PUBLIC KEY", derBytes: serializer.serializedBytes).pemString
    }

    /// Creates a Curve25519 public key for key agreement from a Privacy-Enhanced Mail
    /// (PEM) representation.
    ///
    /// - Parameters:
    ///   - pemRepresentation: A PEM representation of the key.
    public init(pemRepresentation: String) throws {
        let document = try PEMDocument(pemString: pemRepresentation)
        let spki = try SubjectPublicKeyInfo(derEncoded: document.derBytes)
        guard spki.algorithmIdentifier.algorithm == .AlgorithmIdentifier.idX25519 else {
            throw CryptoKitASN1Error.invalidPEMDocument
        }
        self = try .init(rawRepresentation: spki.key.bytes)
    }
}
