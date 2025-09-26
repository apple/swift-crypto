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
import FoundationEssentials
#else
import Foundation
#endif
#endif


@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension HPKE {
	/// Cipher suites to use in hybrid public key encryption (HPKE).
    ///
    /// HPKE cipher suites identify the authenticated encryption with additional data (AEAD) algorithm for encrypting
    /// and decrypting messages, the key derivation function (KDF) for deriving the shared key, and the key encapsulation
    /// mechanism (KEM) for sharing the symmetric key. The sender and recipient of encrypted messages need to use the
    /// same cipher suite.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public struct Ciphersuite: Sendable {
		/// A cipher suite for HPKE that uses NIST P-256 elliptic curve key agreement, SHA-2 key derivation
        /// with a 256-bit digest, and the Advanced Encryption Standard cipher in Galois/Counter Mode with a key length of 256 bits.
        public static let P256_SHA256_AES_GCM_256 = Ciphersuite(kem: .P256_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_256)
        /// A cipher suite that you use for HPKE using NIST P-384 elliptic curve key agreement, SHA-2 key derivation
        /// with a 384-bit digest, and the Advanced Encryption Standard cipher in Galois/Counter Mode with a key length of 256 bits.
        public static let P384_SHA384_AES_GCM_256 = Ciphersuite(kem: .P384_HKDF_SHA384, kdf: .HKDF_SHA384, aead: .AES_GCM_256)
        /// A cipher suite for HPKE that uses NIST P-521 elliptic curve key agreement, SHA-2 key derivation
        /// with a 512-bit digest, and the Advanced Encryption Standard cipher in Galois/Counter Mode with a key length of 256 bits.
        public static let P521_SHA512_AES_GCM_256 = Ciphersuite(kem: .P521_HKDF_SHA512, kdf: .HKDF_SHA512, aead: .AES_GCM_256)
        /// A cipher suite for HPKE that uses X25519 elliptic curve key agreement, SHA-2 key derivation
        /// with a 256-bit digest, and the ChaCha20 stream cipher with the Poly1305 message authentication code.
        public static let Curve25519_SHA256_ChachaPoly = Ciphersuite(kem: .Curve25519_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .chaChaPoly)
        /// A cipher suite for HPKE that uses the X-Wing KEM (ML-KEM-768 with X25519), SHA-2 key derivation
        /// with a 256-bit digest, and the Advanced Encryption Standard cipher in Galois/Counter Mode with a key length of 256 bits.
        public static let XWingMLKEM768X25519_SHA256_AES_GCM_256 = Ciphersuite(kem: .XWingMLKEM768X25519, kdf: .HKDF_SHA256, aead: .AES_GCM_256)

        fileprivate static let ciphersuiteLabel = Data("HPKE".utf8)
        
		/// The key encapsulation mechanism (KEM) for encapsulating the symmetric key.
        public let kem: HPKE.KEM
		/// The key derivation function (KDF) for deriving the symmetric key.
        public let kdf: HPKE.KDF
		/// The authenticated encryption with additional data (AEAD) algorithm for encrypting and decrypting messages.
        public let aead: HPKE.AEAD

        /// Creates an HPKE cipher suite.
        ///
        /// - Parameters:
        ///   - kem: The key encapsulation mechanism for encapsulating the symmetric key.
        ///   - kdf: The key derivation function for deriving the symmetric key.
        ///   - aead: The authenticated encryption with additional data (AEAD) algorithm for encrypting and decrypting messages.
        public init(kem: HPKE.KEM, kdf: HPKE.KDF, aead: HPKE.AEAD) {
            self.kem = kem
            self.kdf = kdf
            self.aead = aead
        }
        
        internal var identifier: Data {
            var identifier = Ciphersuite.ciphersuiteLabel
            identifier.append(kem.identifier)
            identifier.append(kdf.identifier)
            identifier.append(aead.identifier)
            return identifier
        }
    }
}

#endif // Linux or !SwiftPM
