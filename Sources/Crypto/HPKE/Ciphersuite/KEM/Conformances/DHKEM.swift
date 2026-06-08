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
#if CRYPTOKIT_STATIC_LIBRARY
@_exported import CryptoKit_Static
#else
@_exported import CryptoKit
#endif
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
#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, macCatalyst 17.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 16.0, macOS 10.13, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 1.0, *)
#endif
@preconcurrency
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
#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, macCatalyst 17.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 16.0, macOS 10.13, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 1.0, *)
#endif
@preconcurrency
public protocol HPKEDiffieHellmanPublicKey: HPKEPublicKeySerialization, Sendable where EphemeralPrivateKey.PublicKey == Self {
	/// The type of the ephemeral private key.
    associatedtype EphemeralPrivateKey: HPKEDiffieHellmanPrivateKeyGeneration
}

/// A type that represents the public key in HPKE
#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 16.0, macOS 10.13, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 1.0, *)
#endif
@preconcurrency
public protocol HPKEKEMPublicKey: KEMPublicKey, HPKEPublicKeySerialization where EphemeralPrivateKey.PublicKey == Self {
    /// The type of the ephemeral private key.
    associatedtype EphemeralPrivateKey: HPKEKEMPrivateKeyGeneration
}

/// A type that represents the private key in a Diffie-Hellman key exchange.
#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, macCatalyst 17.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 16.0, macOS 10.13, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 1.0, *)
#endif
@preconcurrency
public protocol HPKEDiffieHellmanPrivateKey: Sendable, DiffieHellmanKeyAgreement where PublicKey: HPKEDiffieHellmanPublicKey {}

/// A type that represents the private key in HPKE.
#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 16.0, macOS 10.13, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 1.0, *)
#endif
@preconcurrency
public protocol HPKEKEMPrivateKey: Sendable, KEMPrivateKey where PublicKey: HPKEKEMPublicKey {}

/// A type that represents the generation of private keys in a Diffie-Hellman key exchange.
#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, macCatalyst 17.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 16.0, macOS 10.13, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 1.0, *)
#endif
@preconcurrency
public protocol HPKEDiffieHellmanPrivateKeyGeneration: HPKEDiffieHellmanPrivateKey, Sendable {
	/// Creates a private key generator.
    init()
}

/// A type that represents the generation of private keys in HPKE
#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 16.0, macOS 10.13, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 1.0, *)
#endif
@preconcurrency
public protocol HPKEKEMPrivateKeyGeneration: HPKEKEMPrivateKey, Sendable {
    /// Creates a private key generator.
    init() throws
}

extension HPKE {
	/// A container for Diffie-Hellman key encapsulation mechanisms (KEMs).
    #if !CRYPTOKIT_STATIC_LIBRARY
    @available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, macCatalyst 17.0, *)
    #else // CRYPTOKIT_STATIC_LIBRARY
    @available(iOS 16.0, macOS 10.13, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 1.0, *)
    #endif
    public enum DHKEM: Sendable {
        #if !CRYPTOKIT_STATIC_LIBRARY
        @available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, macCatalyst 17.0, *)
        #else // CRYPTOKIT_STATIC_LIBRARY
        @available(iOS 16.0, macOS 10.13, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 1.0, *)
        #endif
        struct PublicKey<DHPK: HPKEDiffieHellmanPublicKey>: KEMPublicKey where DHPK == DHPK.EphemeralPrivateKey.PublicKey {
            let kem: HPKE.KEM
            let key: DHPK

            #if  !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
            #if CRYPTOKIT_STATIC_LIBRARY
            typealias EncapsulationResult = CryptoKit_Static.KEM.EncapsulationResult
            #else
            typealias EncapsulationResult = CryptoKit.KEM.EncapsulationResult
            #endif
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
        
        #if !CRYPTOKIT_STATIC_LIBRARY
        @available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, macCatalyst 17.0, *)
        #else // CRYPTOKIT_STATIC_LIBRARY
        @available(iOS 16.0, macOS 10.13, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, *)
        #endif
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
