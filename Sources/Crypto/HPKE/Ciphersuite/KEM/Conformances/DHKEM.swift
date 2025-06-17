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
import SwiftSystem
#else
#if canImport(FoundationEssentials)
public import FoundationEssentials
#else
public import Foundation
#endif
#endif

/// A type that ``HPKE`` uses to encode the public key.
@preconcurrency
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public protocol HPKEPublicKeySerialization: Sendable {
	/// Creates a public key from an encoded representation.
	///
	/// - Parameters:
	///  - serialization: The serialized key data.
	///  - kem: The key encapsulation mechanism that the sender used to encapsulate the key.
    init<D: ContiguousBytes>(_ serialization: D, kem: HPKE.KEM) throws
	/// Creates an encoded representation of the public key.
	///
	/// - Parameters:
	///  - kem: The key encapsulation mechanism for encapsulating the key.
    ///  
	/// - Returns: The encoded key data.
    func hpkeRepresentation(kem: HPKE.KEM) throws -> Data
}

/// A type that represents the public key in a Diffie-Hellman key exchange.
@preconcurrency
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public protocol HPKEDiffieHellmanPublicKey: HPKEPublicKeySerialization, Sendable where EphemeralPrivateKey.PublicKey == Self {
	/// The type of the ephemeral private key.
    associatedtype EphemeralPrivateKey: HPKEDiffieHellmanPrivateKeyGeneration
}

/// A type that represents the public key in HPKE
@preconcurrency
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public protocol HPKEKEMPublicKey: KEMPublicKey, HPKEPublicKeySerialization where EphemeralPrivateKey.PublicKey == Self {
    /// The type of the ephemeral private key.
    associatedtype EphemeralPrivateKey: HPKEKEMPrivateKeyGeneration
}

/// A type that represents the private key in a Diffie-Hellman key exchange.
@preconcurrency
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public protocol HPKEDiffieHellmanPrivateKey: Sendable, DiffieHellmanKeyAgreement where PublicKey: HPKEDiffieHellmanPublicKey {}

/// A type that represents the private key in HPKE.
@preconcurrency
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public protocol HPKEKEMPrivateKey: Sendable, KEMPrivateKey where PublicKey: HPKEKEMPublicKey {}

/// A type that represents the generation of private keys in a Diffie-Hellman key exchange.
@preconcurrency
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public protocol HPKEDiffieHellmanPrivateKeyGeneration: HPKEDiffieHellmanPrivateKey, Sendable {
	/// Creates a private key generator.
    init()
}

/// A type that represents the generation of private keys in HPKE
@preconcurrency
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public protocol HPKEKEMPrivateKeyGeneration: HPKEKEMPrivateKey, Sendable {
    /// Creates a private key generator.
    init() throws
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension HPKE {
	/// A container for Diffie-Hellman key encapsulation mechanisms (KEMs).
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum DHKEM: Sendable {
        @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
        struct PublicKey<DHPK: HPKEDiffieHellmanPublicKey>: KEMPublicKey where DHPK == DHPK.EphemeralPrivateKey.PublicKey {
            let kem: HPKE.KEM
            let key: DHPK

            #if  !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
            typealias EncapsulationResult = CryptoKit.KEM.EncapsulationResult
            #else
            typealias EncapsulationResult = Crypto.KEM.EncapsulationResult
            #endif

            init(_ publicKey: DHPK, kem: HPKE.KEM) throws {
                // TODO: Validate Ciphersuite Mismatches
                _ = try publicKey.hpkeRepresentation(kem: kem)
                self.key = publicKey
                self.kem = kem
            }
            
            func encapsulate() throws -> EncapsulationResult {
                let ephemeralKeys = DHPK.EphemeralPrivateKey()
                let dh =
                try ephemeralKeys.sharedSecretFromKeyAgreement(with: key)
                
                let enc = try! ephemeralKeys.publicKey.hpkeRepresentation(kem: kem)
                let selfRepresentation = try self.key.hpkeRepresentation(kem: kem)
                return EncapsulationResult(sharedSecret: HPKE.KexUtils.ExtractAndExpand(dh: dh,
                                                                                            enc: enc,
                                                                                            pkRm: selfRepresentation,
                                                                                            kem: kem,
                                                                                            kdf: kem.kdf), encapsulated: enc)
            }
        }
        
        @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
        struct PrivateKey<DHSK: HPKEDiffieHellmanPrivateKey>: KEMPrivateKey {
            let kem: HPKE.KEM
            let key: DHSK
            
            init(_ privateKey: DHSK, kem: HPKE.KEM) throws {
                // TODO: Validate Ciphersuite Mismatches
                _ = try privateKey.publicKey.hpkeRepresentation(kem: kem)
                self.key = privateKey
                self.kem = kem
            }
            
            static func generate() throws -> Self {
                fatalError("generate() is not available on HPKE.DHKEM.PrivateKey, use generate(kem:) instead.")
            }
            
            public func decapsulate(_ encapsulated: Data) throws -> SymmetricKey {
                let pkE = try DHSK.PublicKey(encapsulated, kem: kem)
                let dh = try key.sharedSecretFromKeyAgreement(with: pkE)
                
                return HPKE.KexUtils.ExtractAndExpand(dh: dh,
                                                      enc: encapsulated,
                                                      pkRm: try key.publicKey.hpkeRepresentation(kem: kem),
                                                      kem: kem, kdf: kem.kdf)
            }
            
            func decapsulate(_ encapsulated: Data, authenticating pkS: DHSK.PublicKey) throws -> SymmetricKey {
                let pkE = try DHSK.PublicKey(encapsulated, kem: kem)
                
                var dh = try Data(unsafeFromContiguousBytes: key.sharedSecretFromKeyAgreement(with: pkE))
                try dh.append(Data(unsafeFromContiguousBytes: key.sharedSecretFromKeyAgreement(with: pkS)))
                
                return HPKE.KexUtils.ExtractAndExpand(dh: dh,
                                                      enc: encapsulated,
                                                      pkRm: try key.publicKey.hpkeRepresentation(kem: kem),
                                                      pkSm: try pkS.hpkeRepresentation(kem: kem),
                                                      kem: kem,
                                                      kdf: kem.kdf)
            }
            
            func authenticateAndEncapsulateTo(_ publicKey: Self.PublicKey) throws -> (sharedSecret: SymmetricKey, encapsulated: Data) {
                let ephemeralKeys = DHSK.PublicKey.EphemeralPrivateKey()
                
                var dh = try Data(unsafeFromContiguousBytes: ephemeralKeys.sharedSecretFromKeyAgreement(with: publicKey.key))
                try dh.append(Data(unsafeFromContiguousBytes: key.sharedSecretFromKeyAgreement(with: publicKey.key)))
                let enc = try ephemeralKeys.publicKey.hpkeRepresentation(kem: kem)
                
                return (HPKE.KexUtils.ExtractAndExpand(dh: dh,
                                                       enc: enc,
                                                       pkRm: try publicKey.key.hpkeRepresentation(kem: kem),
                                                       pkSm: try key.publicKey.hpkeRepresentation(kem: kem),
                                                       kem: kem, kdf: kem.kdf), enc)
            }
            
            var publicKey: HPKE.DHKEM.PublicKey<DHSK.PublicKey> {
                return try! HPKE.DHKEM.PublicKey(key.publicKey, kem: kem)
            }
        }
    }
}

#endif // Linux or !SwiftPM
