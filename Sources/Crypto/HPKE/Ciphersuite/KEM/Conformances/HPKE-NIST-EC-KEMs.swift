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
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
import Foundation



extension P256.KeyAgreement.PrivateKey: HPKEDiffieHellmanPrivateKeyGeneration {
	/// Creates a NIST P-256 elliptic curve private key for use with Diffie-Hellman key exchange.
    public init() {
        self.init(compactRepresentable: false)
    }
}


extension P256.KeyAgreement.PublicKey: HPKEDiffieHellmanPublicKey {
	/// The type of the ephemeral private key associated with this public key.
    public typealias EphemeralPrivateKey = P256.KeyAgreement.PrivateKey
    
    static func validatekem(_ kem: HPKE.KEM) throws {
        switch kem {
        case .P256_HKDF_SHA256: do {}
        default: do {
            throw HPKE.Errors.inconsistentCiphersuiteAndKey
        }
        }
    }
    
	/// Creates a NIST P-256 elliptic curve public key for use with Diffie-Hellman key exchange.
	///
	/// - Parameters:
	///  - serialization: The serialized bytes of the public key.
	///  - kem: The key encapsulation mechanism to use with the public key.
    /// - Throws: ``CryptoKit/HPKE/Errors/inconsistentCiphersuiteAndKey`` if the key encapsulation mechanism requested is incompatible with this public key.
    public init<D>(_ serialization: D, kem: HPKE.KEM) throws where D: ContiguousBytes {
        try Self.validatekem(kem)
        try self.init(x963Representation: serialization)
    }
    
	/// Creates a serialized representation of the public key.
	///
	/// - Parameters:
	///  - kem: The Key Encapsulation Mechanism to use with the public key.
	/// - Returns: The serialized representation of the public key.
    /// - Throws: ``CryptoKit/HPKE/Errors/inconsistentCiphersuiteAndKey`` if the key encapsulation mechanism requested is incompatible with this public key.
    public func hpkeRepresentation(kem: HPKE.KEM) throws -> Data {
        try Self.validatekem(kem)
        return self.x963Representation
    }
    
	/// The type of the ephemeral private key associated with this public key.
    public typealias HPKEEphemeralPrivateKey = P256.KeyAgreement.PrivateKey
}


extension P384.KeyAgreement.PrivateKey: HPKEDiffieHellmanPrivateKeyGeneration {
	/// Creates a NIST P-384 elliptic curve private key for use with Diffie-Hellman key exchange.
    public init() {
        self.init(compactRepresentable: false)
    }
}


extension P384.KeyAgreement.PublicKey: HPKEDiffieHellmanPublicKey {
	/// The type of the ephemeral private key associated with this public key.
    public typealias EphemeralPrivateKey = P384.KeyAgreement.PrivateKey
    
    static func validatekem(_ kem: HPKE.KEM) throws {
        switch kem {
        case .P384_HKDF_SHA384: do {}
        default: do {
            throw HPKE.Errors.inconsistentCiphersuiteAndKey
        }
        }
    }
    
	/// Creates a NIST P-384 elliptic curve public key for use with Diffie-Hellman key exchange.
	///
	/// - Parameters:
	///  - serialization: The serialized bytes of the public key.
	///  - kem: The Key Encapsulation Mechanism to use with the public key.
    ///
    /// - Throws: ``CryptoKit/HPKE/Errors/inconsistentCiphersuiteAndKey`` if the key encapsulation mechanism requested is incompatible with this public key.
    public init<D>(_ serialization: D, kem: HPKE.KEM) throws where D: ContiguousBytes {
        try Self.validatekem(kem)
        try self.init(x963Representation: serialization)
    }
    
	/// Creates a serialized representation of the public key.
	///
	/// - Parameters:
	///  - kem: The Key Encapsulation Mechanism to use with the public key.
    ///
	/// - Returns: The serialized representation of the public key.
    ///
    /// - Throws: ``CryptoKit/HPKE/Errors/inconsistentCiphersuiteAndKey`` if the key encapsulation mechanism requested is incompatible with this public key.
    public func hpkeRepresentation(kem: HPKE.KEM) throws -> Data {
        try Self.validatekem(kem)
        return self.x963Representation
    }
}


extension P521.KeyAgreement.PrivateKey: HPKEDiffieHellmanPrivateKeyGeneration {
	/// Creates a NIST P-521 elliptic curve private key for use with Diffie-Hellman key exchange.
    public init() {
        self.init(compactRepresentable: false)
    }
}


extension P521.KeyAgreement.PublicKey: HPKEDiffieHellmanPublicKey {
	/// The type of the ephemeral private key associated with this public key.
    public typealias EphemeralPrivateKey = P521.KeyAgreement.PrivateKey
    
    static func validatekem(_ kem: HPKE.KEM) throws {
        switch kem {
        case .P521_HKDF_SHA512: do {}
        default: do {
            throw HPKE.Errors.inconsistentCiphersuiteAndKey
        }
        }
    }
    
	/// Creates a NIST P-521 elliptic curve public key for use with Diffie-Hellman key exchange.
	///
	/// - Parameters:
	///  - serialization: The serialized bytes of the public key.
	///  - kem: The Key Encapsulation Mechanism to use with the public key.
    ///
    /// - Throws: ``CryptoKit/HPKE/Errors/inconsistentCiphersuiteAndKey`` if the key encapsulation mechanism requested is incompatible with this public key.
    public init<D>(_ serialization: D, kem: HPKE.KEM) throws where D: ContiguousBytes {
        try Self.validatekem(kem)
        try self.init(x963Representation: serialization)
    }
    
	/// Creates a serialized representation of the public key.
	///
	/// - Parameters:
	///  - kem: The Key Encapsulation Mechanism to use with the public key.
    ///
	/// - Returns: The serialized representation of the public key.
    ///
    /// - Throws: ``CryptoKit/HPKE/Errors/inconsistentCiphersuiteAndKey`` if the key encapsulation mechanism requested is incompatible with this public key.
    public func hpkeRepresentation(kem: HPKE.KEM) throws -> Data {
        try Self.validatekem(kem)
        return self.x963Representation
    }
    
	/// The type of the ephemeral private key associated with this public key.
    public typealias HPKEEphemeralPrivateKey = P521.KeyAgreement.PrivateKey
}

#endif // Linux or !SwiftPM
