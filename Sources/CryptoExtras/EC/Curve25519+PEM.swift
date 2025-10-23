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
import Foundation
import SwiftASN1

@available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
extension Curve25519.Signing.PrivateKey {
    /// A Distinguished Encoding Rules (DER) encoded representation of the private key.
    public var derRepresentation: Data {
        let pkey = ASN1.PKCS8PrivateKey(algorithm: .ed25519, privateKey: Array(self.rawRepresentation))
        var serializer = DER.Serializer()

        try! serializer.serialize(pkey)
        return Data(serializer.serializedBytes)
    }

    /// A Privacy-Enhanced Mail (PEM) representation of the private key.
    public var pemRepresentation: String {
        let pemDocument = ASN1.PEMDocument(type: "PRIVATE KEY", derBytes: self.derRepresentation)
        return pemDocument.pemString
    }

    /// Creates a Curve25519 private key for signing from a Privacy-Enhanced Mail
    /// (PEM) representation.
    ///
    /// - Parameters:
    ///   - pemRepresentation: A PEM representation of the key.
    public init(pemRepresentation: String) throws {
        let document = try ASN1.PEMDocument(pemString: pemRepresentation)
        self = try .init(derRepresentation: document.derBytes)
    }

    /// Creates a Curve25519 private key for signing from a Distinguished Encoding
    /// Rules (DER) encoded representation.
    ///
    /// - Parameters:
    ///   - derRepresentation: A DER-encoded representation of the key.
    public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws where Bytes.Element == UInt8 {
        let bytes = Array(derRepresentation)
        let key = try ASN1.PKCS8PrivateKey(derEncoded: bytes)
        self = try .init(rawRepresentation: key.privateKey.bytes)
    }
}

@available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
extension Curve25519.Signing.PublicKey {
    /// A Distinguished Encoding Rules (DER) encoded representation of the public key.
    public var derRepresentation: Data {
        let spki = SubjectPublicKeyInfo(algorithmIdentifier: .ed25519, key: Array(self.rawRepresentation))
        var serializer = DER.Serializer()

        try! serializer.serialize(spki)
        return Data(serializer.serializedBytes)
    }

    /// A Privacy-Enhanced Mail (PEM) representation of the public key.
    public var pemRepresentation: String {
        let pemDocument = ASN1.PEMDocument(type: "PUBLIC KEY", derBytes: self.derRepresentation)
        return pemDocument.pemString
    }

    /// Creates a Curve25519 public key for signing from a Privacy-Enhanced Mail
    /// (PEM) representation.
    ///
    /// - Parameters:
    ///   - pemRepresentation: A PEM representation of the key.
    public init(pemRepresentation: String) throws {
        let document = try ASN1.PEMDocument(pemString: pemRepresentation)
        self = try .init(derRepresentation: document.derBytes)
    }

    /// Creates a Curve25519 public key for signing from a Distinguished Encoding
    /// Rules (DER) encoded representation.
    ///
    /// - Parameters:
    ///   - derRepresentation: A DER-encoded representation of the key.
    public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws where Bytes.Element == UInt8 {
        let bytes = Array(derRepresentation)
        let spki = try SubjectPublicKeyInfo(derEncoded: bytes)
        guard spki.algorithmIdentifier == .ed25519 else {
            throw CryptoKitASN1Error.invalidASN1Object
        }
        self = try .init(rawRepresentation: spki.key.bytes)
    }
}

@available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
extension Curve25519.KeyAgreement.PrivateKey {
    /// A Distinguished Encoding Rules (DER) encoded representation of the private key.
    public var derRepresentation: Data {
        let pkey = ASN1.PKCS8PrivateKey(algorithm: .x25519, privateKey: Array(self.rawRepresentation))
        var serializer = DER.Serializer()

        // Serializing this key can't throw
        try! serializer.serialize(pkey)
        return Data(serializer.serializedBytes)
    }

    /// A Privacy-Enhanced Mail (PEM) representation of the private key.
    public var pemRepresentation: String {
        let pemDocument = ASN1.PEMDocument(type: "PRIVATE KEY", derBytes: self.derRepresentation)
        return pemDocument.pemString
    }

    /// Creates a Curve25519 private key for key agreement from a Privacy-Enhanced Mail
    /// (PEM) representation.
    ///
    /// - Parameters:
    ///   - pemRepresentation: A PEM representation of the key.
    public init(pemRepresentation: String) throws {
        let document = try ASN1.PEMDocument(pemString: pemRepresentation)
        self = try .init(derRepresentation: document.derBytes)
    }

    /// Creates a Curve25519 private key for key agreement from a Distinguished Encoding
    /// Rules (DER) encoded representation.
    ///
    /// - Parameters:
    ///   - derRepresentation: A DER-encoded representation of the key.
    public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws where Bytes.Element == UInt8 {
        let bytes = Array(derRepresentation)
        let key = try ASN1.PKCS8PrivateKey(derEncoded: bytes)
        self = try .init(rawRepresentation: key.privateKey.bytes)
    }
}

@available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
extension Curve25519.KeyAgreement.PublicKey {
    /// A Distinguished Encoding Rules (DER) encoded representation of the public key.
    public var derRepresentation: Data {
        let spki = SubjectPublicKeyInfo(algorithmIdentifier: .x25519, key: Array(self.rawRepresentation))
        var serializer = DER.Serializer()

        try! serializer.serialize(spki)
        return Data(serializer.serializedBytes)
    }

    /// A Privacy-Enhanced Mail (PEM) representation of the public key.
    public var pemRepresentation: String {
        let pemDocument = ASN1.PEMDocument(type: "PUBLIC KEY", derBytes: self.derRepresentation)
        return pemDocument.pemString
    }

    /// Creates a Curve25519 public key for key agreement from a Privacy-Enhanced Mail
    /// (PEM) representation.
    ///
    /// - Parameters:
    ///   - pemRepresentation: A PEM representation of the key.
    public init(pemRepresentation: String) throws {
        let document = try ASN1.PEMDocument(pemString: pemRepresentation)
        self = try .init(derRepresentation: document.derBytes)
    }

    /// Creates a Curve25519 public key for key agreement from a Distinguished Encoding
    /// Rules (DER) encoded representation.
    ///
    /// - Parameters:
    ///   - derRepresentation: A DER-encoded representation of the key.
    public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws where Bytes.Element == UInt8 {
        let bytes = Array(derRepresentation)
        let spki = try SubjectPublicKeyInfo(derEncoded: bytes)
        guard spki.algorithmIdentifier == .x25519 else {
            throw CryptoKitASN1Error.invalidASN1Object
        }
        self = try .init(rawRepresentation: spki.key.bytes)
    }
}
