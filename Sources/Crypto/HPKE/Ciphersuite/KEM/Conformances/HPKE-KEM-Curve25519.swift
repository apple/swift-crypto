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

#if CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
public import SwiftSystem
#else
#if canImport(FoundationEssentials)
public import FoundationEssentials
#else
public import Foundation
#endif
#endif


@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Curve25519.KeyAgreement.PrivateKey: HPKEDiffieHellmanPrivateKeyGeneration {}


@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Curve25519.KeyAgreement.PublicKey: HPKEDiffieHellmanPublicKey {
	/// The type of the ephemeral private key associated with this public key.
    public typealias EphemeralPrivateKey = Curve25519.KeyAgreement.PrivateKey
    
    static func validateCiphersuite(_ kem: HPKE.KEM) throws {
        switch kem {
        case .Curve25519_HKDF_SHA256: do {}
        default: do {
            throw HPKE.Errors.inconsistentCiphersuiteAndKey
        }
        }
    }
    
	/// Creates a Curve25519 elliptic curve public key for use with Diffie-Hellman key exchange.
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
    public typealias HPKEEphemeralPrivateKey = Curve25519.KeyAgreement.PrivateKey
}

#endif // Linux or !SwiftPM
