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

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

#if (!CRYPTO_IN_SWIFTPM_FORCE_BUILD_API) || CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias XWingPublicKeyImpl = CoreCryptoXWingPublicKeyImpl
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias XWingPrivateKeyImpl = CoreCryptoXWingPrivateKeyImpl
#else
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias XWingPublicKeyImpl = OpenSSLXWingPublicKeyImpl
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias XWingPrivateKeyImpl = OpenSSLXWingPrivateKeyImpl
#endif

/// The X-Wing (ML-KEM768 with X25519) Key Encapsulation Mechanism, defined in
/// https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-06
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public enum XWingMLKEM768X25519: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension XWingMLKEM768X25519 {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public struct PublicKey: KEMPublicKey {
        var impl: XWingPublicKeyImpl

        internal init(impl: XWingPublicKeyImpl) {
            self.impl = impl
        }

        public init<D: ContiguousBytes>(rawRepresentation: D) throws {
            self.impl = try .init(rawRepresentation: rawRepresentation)
        }

        public var rawRepresentation: Data {
            get {
                self.impl.rawRepresentation
            }
        }

        public func encapsulate() throws -> KEM.EncapsulationResult {
            return try self.impl.encapsulate()
        }
    }

    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public struct PrivateKey: KEMPrivateKey {
        private var impl: XWingPrivateKeyImpl

        public var seedRepresentation: Data {
            get {
                self.impl.seedRepresentation
            }
        }

        public var integrityCheckedRepresentation: Data {
            get {
                self.impl.integrityCheckedRepresentation
            }
        }

        internal init(impl: XWingPrivateKeyImpl) {
            self.impl = impl
        }

        internal init<D: DataProtocol>(seedRepresentation: D, publicKeyHash: SHA3_256Digest?) throws {
            self.impl = try .init(seedRepresentation: seedRepresentation, publicKeyHash: publicKeyHash)
        }

        public static func generate() throws -> XWingMLKEM768X25519.PrivateKey {
            return try Self(impl: XWingPrivateKeyImpl.generate())
        }

        public func decapsulate(_ encapsulated: Data) throws -> SymmetricKey {
            try self.impl.decapsulate(encapsulated)
        }

        public var publicKey: XWingMLKEM768X25519.PublicKey {
            get {
                XWingMLKEM768X25519.PublicKey(impl: self.impl.publicKey)
            }
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension XWingMLKEM768X25519.PrivateKey: HPKEKEMPrivateKeyGeneration {
    public init() throws {
        self = try Self.generate()
    }

    public init<D: DataProtocol>(seedRepresentation: D, publicKey: XWingMLKEM768X25519.PublicKey?) throws {
        var publicKeyHash: SHA3_256Digest? = nil
        if publicKey != nil {
            publicKeyHash = SHA3_256.hash(data: publicKey!.rawRepresentation)
        }

        self = try XWingMLKEM768X25519.PrivateKey.init(seedRepresentation: seedRepresentation, publicKeyHash: publicKeyHash)
    }

    public init<D: DataProtocol>(integrityCheckedRepresentation: D) throws {
        let seed = integrityCheckedRepresentation.dropLast(32) // sizeof(SHA3-256 digest)
        let publicKeyHashBytes = integrityCheckedRepresentation.dropFirst(32)
        let publicKeyHash = SHA3_256Digest(bytes: [UInt8](publicKeyHashBytes))

        self = try XWingMLKEM768X25519.PrivateKey.init(seedRepresentation: seed, publicKeyHash: publicKeyHash)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension XWingMLKEM768X25519.PublicKey: HPKEKEMPublicKey {
    /// The type of the ephemeral private key associated with this public key.
    public typealias EphemeralPrivateKey = XWingMLKEM768X25519.PrivateKey

    static func validateCiphersuite(_ kem: HPKE.KEM) throws {
        switch kem {
            case .XWingMLKEM768X25519: do {}
            default: do {
                throw HPKE.Errors.inconsistentCiphersuiteAndKey
            }
        }
    }

    /// Creates an X-Wing public key for use with HPKE.
    ///
    /// - Parameters:
    ///  - serialization: The serialized bytes of the public key.
    ///  - kem: The key encapsulation mechanism to use with the public key.
    ///
    /// - Throws: ``CryptoKit/HPKE/Errors/inconsistentCiphersuiteAndKey`` if the key encapsulation mechanism requested is incompatible with this public key.
    public init<D>(_ serialization: D, kem: HPKE.KEM) throws where D: ContiguousBytes {
        try Self.validateCiphersuite(kem)
        try self.init(rawRepresentation: serialization)
    }

    /// Creates a serialized representation of the public key.
    ///
    /// - Parameters:
    ///  - kem: The Key Encapsulation Mechanism to use with the public key.
    ///
    /// - Throws: ``CryptoKit/HPKE/Errors/inconsistentCiphersuiteAndKey`` if the key encapsulation mechanism requested is incompatible with this public key.
    ///
    /// - Returns: The serialized representation of the public key.
    public func hpkeRepresentation(kem: HPKE.KEM) throws -> Data {
        try Self.validateCiphersuite(kem)
        return self.rawRepresentation
    }

    /// The type of the ephemeral private key associated with this public key.
    public typealias HPKEEphemeralPrivateKey = XWingMLKEM768X25519.PrivateKey
}
#endif // Linux or !SwiftPM
