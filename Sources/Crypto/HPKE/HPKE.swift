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

/// A container for hybrid public key encryption (HPKE) operations.
///
/// Hybrid public key encryption (HPKE) uses a symmetric encryption algorithm to encrypt data, and encapsulates the symmetric
/// encryption material using a public key encryption algorithm.
///
/// HPKE ensures that the ciphertext wasn't tampered with after its creation. It can also check the validity
/// of additional cleartext data in apps where you need to send headers or other metadata as cleartext.
///
/// HPKE optionally incorporates sender authentication, allowing the recipient to validate the authenticity of
/// messages using the sender's public key.
///
/// HPKE is described in the Internet Research Task Force (IRTF) document
/// [RFC 9180](https://www.ietf.org/rfc/rfc9180.pdf).
///
/// ## Topics
///
/// ### Sending and receiving messages
///  - ``Sender``
///  - ``Recipient``
///
/// ### Choosing cryptographic algorithms
///  - ``Ciphersuite``
///  - ``AEAD``
///  - ``KDF``
///  - ``KEM``
///  - ``DHKEM``
///
/// ### Handling errors
///  - ``Errors``
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public enum HPKE: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension HPKE {
    /// Static constant used to store the fixed-string label for the HPKE export API
    /// See: https://datatracker.ietf.org/doc/html/rfc9180#name-secret-export
    fileprivate static let exportLabel = Data("sec".utf8)

    /// A type that represents the sending side of an HPKE message exchange.
    ///
    /// To create encrypted messages, initialize a `Sender` specifying the appropriate cipher suite,
    /// the recipient's public key, and the additional cryptographic material relevant to your chosen mode of operation.
    /// Call ``seal(_:)`` or ``seal(_:authenticating:)`` on the `Sender` instance for each message
    /// in turn to retrieve its ciphertext. The recipient of the messages needs to process them in the
    /// same order as the `Sender`, using the same encryption mode, cipher suite, and key schedule information
    ///  (`info`), as well as the `Sender`'s ``encapsulatedKey``.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public struct Sender: Sendable {
        private var context: Context
        /// The encapsulated symmetric key that the recipient uses to decrypt messages.
        public let encapsulatedKey: Data
        
        /// The exporter secret.
        internal var exporterSecret: SymmetricKey {
            return context.keySchedule.exporterSecret
        }
        
        /// Exports a secret given domain-separation context and the desired output length.
        /// - Parameters:
        ///   - context: Application-specific information providing context on the use of this key.
        ///   - outputByteCount: The desired length of the exported secret.
        /// - Returns: The exported secret.
        public func exportSecret<Context: DataProtocol>(context: Context, outputByteCount: Int) throws -> SymmetricKey {
            precondition(outputByteCount > 0);
            return LabeledExpand(prk: self.exporterSecret,
                                 label: exportLabel,
                                 info: context,
                                 outputByteCount: UInt16(outputByteCount),
                                 suiteID: self.context.keySchedule.ciphersuite.identifier,
                                 kdf: self.context.keySchedule.ciphersuite.kdf)
        }
        
        /// Creates a sender in base mode.
        ///
        /// The `Sender` encrypts messages in base mode with a symmetric encryption key it derives using a key derivation function (KDF).
		/// The KDF uses the key schedule data in `info` as input to generate the key.
		/// The `Sender` encapsulates the derived key using the recipient's public key.
        /// You access the encapsulated key using ``encapsulatedKey``.
        ///
        /// - Parameters:
        ///   - recipientKey: The recipient's public key for encrypting the messages.
        ///   - ciphersuite: The cipher suite that defines the cryptographic algorithms to use.
        ///   - info: Data that the key derivation function uses to compute the symmetric key material. The sender and the recipient need to use the same `info` data.
        /// - Note: The system throws errors from ``CryptoKit/HPKE/Errors`` when it encounters them.
        public init<PK: HPKEDiffieHellmanPublicKey>(recipientKey: PK, ciphersuite: Ciphersuite, info: Data) throws {
            self.context = try Context(senderRoleWithCiphersuite: ciphersuite, mode: .base, psk: nil, pskID: nil, pkR: recipientKey, info: info)
            self.encapsulatedKey = context.encapsulated
        }

        /// Creates a sender in base mode.
        ///
        /// The `Sender` encrypts messages in base mode with a symmetric encryption key it derives using a key derivation function (KDF).
        /// The KDF uses the key schedule data in `info` as input to generate the key.
        /// The `Sender` encapsulates the derived key using the recipient's public key.
        /// You access the encapsulated key using ``encapsulatedKey``.
        ///
        /// - Parameters:
        ///   - recipientKey: The recipient's public key for encrypting the messages.
        ///   - ciphersuite: The cipher suite that defines the cryptographic algorithms to use.
        ///   - info: Data that the key derivation function uses to compute the symmetric key material. The sender and the recipient need to use the same `info` data.
        /// - Note: The system throws errors from ``CryptoKit/HPKE/Errors`` when it encounters them.
        public init<PK: HPKEKEMPublicKey>(recipientKey: PK, ciphersuite: Ciphersuite, info: Data) throws {
            self.context = try Context(senderRoleWithCiphersuite: ciphersuite, mode: .base, psk: nil, pskID: nil, pkR: recipientKey, info: info)
            self.encapsulatedKey = context.encapsulated
        }

        /// Creates a sender in preshared key (PSK) mode.
        ///
        /// The `Sender` encrypts messages in PSK mode using a symmetric encryption key that the sender and recipient both know in advance, in combination with a key it derives using a key derivation function (KDF) and
		/// the key schedule data in `info`.
        /// The `Sender` encapsulates the derived key using the recipient's public key.
        /// You access the encapsulated key using ``encapsulatedKey``.
        ///
        /// - Parameters:
        ///   - recipientKey: The recipient's public key for encrypting the messages.
        ///   - ciphersuite: The cipher suite that defines the cryptographic algorithms to use.
        ///   - info: Data that the key derivation function uses to compute the symmetric key material. The sender and the recipient need to use the same `info` data.
        ///   - psk: A preshared key (PSK) that the sender and the recipient both hold.
        ///   - pskID: An identifier for the PSK.
        /// - Note: The system throws errors from ``CryptoKit/HPKE/Errors`` when it encounters them.
        public init<PK: HPKEDiffieHellmanPublicKey>(recipientKey: PK, ciphersuite: Ciphersuite, info: Data, presharedKey psk: SymmetricKey, presharedKeyIdentifier pskID: Data) throws {
            self.context = try Context(senderRoleWithCiphersuite: ciphersuite, mode: .psk, psk: psk, pskID: pskID, pkR: recipientKey, info: info)
            self.encapsulatedKey = context.encapsulated
        }
        
        /// Creates a sender in authentication mode.
        ///
        /// The `Sender` encrypts messages in authentication mode with a symmetric encryption key.
        /// Messages also include authentication data so that the recipient can verify the authenticity of the sender’s private key.
        ///
        /// - Parameters:
        ///   - recipientKey: The recipient's public key for encrypting the messages.
        ///   - ciphersuite: The cipher suite that defines the cryptographic algorithms to use.
        ///   - info: Data that the key derivation function uses to compute the symmetric key material. The sender and the recipient need to use the same `info` data.
        ///   - authenticationKey: The sender's private key for generating the HMAC.
        /// - Note: The system throws errors from ``CryptoKit/HPKE/Errors`` when it encounters them.
        public init<SK: HPKEDiffieHellmanPrivateKey>(recipientKey: SK.PublicKey, ciphersuite: Ciphersuite, info: Data, authenticatedBy authenticationKey: SK) throws {
            self.context = try Context(senderRoleWithCiphersuite: ciphersuite, mode: .auth, psk: nil, pskID: nil, pkR: recipientKey, info: info, skS: authenticationKey)
            self.encapsulatedKey = context.encapsulated
        }
        
        /// Creates a sender in authentication and preshared key mode.
        ///
        /// The `Sender` encrypts messages in authentication and preshared key (`auth_psk`) mode using
        /// a symmetric encryption key that the sender and recipient both know in advance, in combination with a key it derives using a key derivation function (KDF) and
		/// the key schedule data in `info`.
        /// Messages also include authentication data so that the recipient can verify the authenticity of the sender’s private key.
        ///
        /// - Parameters:
        ///   - recipientKey: The recipient's public key for encrypting the messages.
        ///   - ciphersuite: The cipher suite that defines the cryptographic algorithms to use.
        ///   - info: Data that the key derivation function uses to compute the symmetric key material. The sender and the recipient need to use the same `info` data.
        ///   - authenticationKey: The sender's private key for generating the HMAC.
        ///   - psk: A preshared key (PSK) that the sender and the recipient both hold.
        ///   - pskID: An identifier for the PSK.
        /// - Note: The system throws errors from ``CryptoKit/HPKE/Errors`` when it encounters them.
        public init<SK: HPKEDiffieHellmanPrivateKey>(recipientKey: SK.PublicKey, ciphersuite: Ciphersuite, info: Data, authenticatedBy authenticationKey: SK, presharedKey psk: SymmetricKey, presharedKeyIdentifier pskID: Data) throws {
            self.context = try Context(senderRoleWithCiphersuite: ciphersuite, mode: .auth_psk, psk: psk, pskID: pskID, pkR: recipientKey, info: info, skS: authenticationKey)
            self.encapsulatedKey = context.encapsulated
        }
        
        /// Encrypts the given cleartext message and attaches additional authenticated data.
        ///
        /// You can call this method multiple times to encrypt a series of messages.
        /// When using this method, you need to supply ciphertext messages to the decryption
        /// code on the receiving side in the same order as you encrypt them.
        ///
        /// - Parameters:
        ///   - msg: The cleartext message to encrypt.
        ///   - aad: Additional data that the `Sender` authenticates and adds to the message in cleartext.
        /// - Note: The system throws errors from ``CryptoKit/HPKE/Errors`` when it encounters them.
        /// - Returns: The ciphertext for the recipient to decrypt.
        public mutating func seal<M: DataProtocol, AD: DataProtocol>(_ msg: M, authenticating aad: AD) throws -> Data {
            return try context.keySchedule.seal(msg, authenticating: aad)
        }
        
        /// Encrypts the given cleartext message.
        ///
        /// You can call this method multiple times to encrypt a series of messages.
        /// When using this method, you need to supply ciphertext messages to the decryption
        /// code on the receiving side in the same order as you encrypt them.
        ///
        /// - Parameters:
        ///   - msg: The cleartext message to encrypt.
        /// - Note: The system throws errors from ``CryptoKit/HPKE/Errors`` when it encounters them.
        /// - Returns: The ciphertext for the recipient to decrypt.
        public mutating func seal<M: DataProtocol>(_ msg: M) throws -> Data {
            return try context.keySchedule.seal(msg, authenticating: Data())
        }
    }
    
    /// A type that represents the receiving side of an HPKE message exchange.
    ///
    /// To decrypt and verify the identity of encrypted messages, initialize a `Recipient` specifying the appropriate
    /// cipher suite, the receiver's private key, the encapsulated symmetric key, and the additional cryptographic
    /// material relevant to your chosen mode of operation.
    /// Call ``open(_:)`` or ``open(_:authenticating:)`` on the `Recipient` instance for each message
    /// in turn to retrieve its cleartext. The recipient of the messages needs to process them in the
    /// same order as the `Sender`, using the same cipher suite, encryption mode, and key schedule information
    /// (`info` data).
    /// Use a separate `Recipient` instance for each stream of messages.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public struct Recipient: Sendable {
        
        private var context: Context
        
        /// The exporter secret.
        internal var exporterSecret: SymmetricKey {
            return context.keySchedule.exporterSecret
        }
        
        /// Exports a secret given domain-separation context and the desired output length.
        /// - Parameters:
        ///   - context: Application-specific information providing context on the use of this key.
        ///   - outputByteCount: The desired length of the exported secret.
        /// - Returns: The exported secret.
        public func exportSecret<Context: DataProtocol>(context: Context, outputByteCount: Int) throws -> SymmetricKey {
            precondition(outputByteCount > 0);
            return LabeledExpand(prk: self.exporterSecret,
                                 label: exportLabel,
                                 info: context,
                                 outputByteCount: UInt16(outputByteCount),
                                 suiteID: self.context.keySchedule.ciphersuite.identifier,
                                 kdf: self.context.keySchedule.ciphersuite.kdf)
        }
        
        /// Creates a recipient in base mode.
        ///
        /// The `Receiver` decrypts messages in base mode using the encapsulated key with the key schedule information (`info` data).
        ///
        /// - Parameters:
        ///   - privateKey: The recipient's private key for decrypting the incoming messages.
        ///   - ciphersuite: The cipher suite that defines the cryptographic algorithms to use.
        ///   - info: Data that the key derivation function uses to compute the symmetric key material. The sender and the recipient need to use the same `info` data.
        ///   - encapsulatedKey: The encapsulated symmetric key that the sender provides.
        /// - Note: The system throws errors from ``CryptoKit/HPKE/Errors`` when it encounters them.
        public init<SK: HPKEDiffieHellmanPrivateKey>(privateKey: SK, ciphersuite: Ciphersuite, info: Data, encapsulatedKey: Data) throws {
            self.context = try Context(recipientRoleWithCiphersuite: ciphersuite, mode: .base, enc: encapsulatedKey, psk: nil, pskID: nil, skR: privateKey, info: info, pkS: nil)
        }

        /// Creates a recipient in base mode.
        ///
        /// The `Receiver` decrypts messages in base mode using the encapsulated key with the key schedule information (`info` data).
        ///
        /// - Parameters:
        ///   - privateKey: The recipient's private key for decrypting the incoming messages.
        ///   - ciphersuite: The cipher suite that defines the cryptographic algorithms to use.
        ///   - info: Data that the key derivation function uses to compute the symmetric key material. The sender and the recipient need to use the same `info` data.
        ///   - encapsulatedKey: The encapsulated symmetric key that the sender provides.
        /// - Note: The system throws errors from ``CryptoKit/HPKE/Errors`` when it encounters them.
        public init<SK: HPKEKEMPrivateKey>(privateKey: SK, ciphersuite: Ciphersuite, info: Data, encapsulatedKey: Data) throws {
            self.context = try Context(recipientRoleWithCiphersuite: ciphersuite, mode: .base, enc: encapsulatedKey, psk: nil, pskID: nil, skR: privateKey, info: info, pkS: nil)
        }

        /// Creates a recipient in preshared key (PSK) mode.
        ///
        /// The `Receiver` decrypts messages in PSK mode using the encapsulated key with the key schedule information (`info` data),
		/// in addition to a symmetric encryption key that the sender and recipient both know in advance.
        ///
        /// - Parameters:
        ///   - privateKey: The recipient's private key for decrypting the incoming messages.
        ///   - ciphersuite: The cipher suite that defines the cryptographic algorithms to use.
        ///   - info: Data that the key derivation function uses to compute the symmetric key material. The sender and the recipient need to use the same `info` data.
        ///   - encapsulatedKey: The encapsulated symmetric key that the sender provides.
        ///   - psk: A preshared key (PSK) that the sender and the recipient both hold.
        ///   - pskID: An identifier for the PSK.
        /// - Note: The system throws errors from ``CryptoKit/HPKE/Errors`` when it encounters them.
        public init<SK: HPKEDiffieHellmanPrivateKey>(privateKey: SK, ciphersuite: Ciphersuite, info: Data, encapsulatedKey: Data, presharedKey psk: SymmetricKey, presharedKeyIdentifier pskID: Data) throws {
            self.context = try Context(recipientRoleWithCiphersuite: ciphersuite, mode: .psk, enc: encapsulatedKey, psk: psk, pskID: pskID, skR: privateKey, info: info, pkS: nil)
        }
        
        /// Creates a recipient in authentication mode.
        ///
        /// The `Receiver` decrypts messages in authentication mode using the encapsulated key with the key schedule information (`info` data).
        /// Messages also include authentication data so that the recipient can verify the authenticity of the sender’s private key.
        ///
        /// - Parameters:
        ///   - privateKey: The recipient's private key for decrypting the incoming messages.
        ///   - ciphersuite: The cipher suite that defines the cryptographic algorithms to use.
        ///   - info: Data that the key derivation function uses to compute the symmetric key material. The sender and the recipient need to use the same `info` data.
        ///   - encapsulatedKey: The encapsulated symmetric key that the sender provides.
        ///   - authenticationKey: The sender's public key for authenticating the messages.
        /// - Note: The system throws errors from ``CryptoKit/HPKE/Errors`` when it encounters them.
        public init<SK: HPKEDiffieHellmanPrivateKey>(privateKey: SK, ciphersuite: Ciphersuite, info: Data, encapsulatedKey: Data, authenticatedBy authenticationKey: SK.PublicKey) throws {
            self.context = try Context(recipientRoleWithCiphersuite: ciphersuite, mode: .auth, enc: encapsulatedKey, psk: nil, pskID: nil, skR: privateKey, info: info, pkS: authenticationKey)
        }
        
        /// Creates a recipient in authentication and preshared key mode.
        ///
        /// The `Receiver` decrypts messages it receives in authentication and preshared key (`auth_psk`) mode
        /// using the encapsulated key with the key schedule information (`info` data),
		/// in addition to a symmetric encryption key that the sender and recipient both know in advance.
        /// Messages also include authentication data so that the recipient can verify the authenticity of the sender’s private key.
        ///
        /// - Parameters:
        ///   - privateKey: The recipient's private key for decrypting the incoming messages.
        ///   - ciphersuite: The cipher suite that defines the cryptographic algorithms to use.
        ///   - info: Data that the key derivation function uses to compute the symmetric key material. The sender and the recipient need to use the same `info` data.
        ///   - encapsulatedKey: The encapsulated symmetric key that the sender provides.
        ///   - authenticationKey: The sender's public key for authenticating the messages.
        ///   - psk: A preshared key (PSK) that the sender and the recipient both hold.
        ///   - pskID: An identifier for the PSK.
        /// - Note: The system throws errors from ``CryptoKit/HPKE/Errors`` when it encounters them.
        public init<SK: HPKEDiffieHellmanPrivateKey>(privateKey: SK, ciphersuite: Ciphersuite, info: Data, encapsulatedKey: Data, authenticatedBy  authenticationKey: SK.PublicKey, presharedKey psk: SymmetricKey, presharedKeyIdentifier pskID: Data) throws {
            self.context = try Context(recipientRoleWithCiphersuite: ciphersuite, mode: .auth_psk, enc: encapsulatedKey, psk: psk, pskID: pskID, skR: privateKey, info: info, pkS: authenticationKey)
        }
        
        /// Decrypts a message, if the ciphertext is valid, verifying the integrity of additional authentication data.
        ///
        /// You can call this method multiple times to decrypt a series of messages.
        /// When using this method, the recipient of the ciphertext messages needs to decrypt
        /// them in the same order that the sender encrypts them.
        /// The system doesn't decrypt the additional authentication data in the `aad` parameter
        /// that the recipient uses to verify the message integrity.
        ///
        /// - Parameters:
        ///   - ciphertext: The ciphertext message to decrypt.
        ///   - aad: Additional cleartext data to authenticate.
        /// - Note: The system throws errors from ``CryptoKit/HPKE/Errors`` when it encounters them.
        /// - Returns: The resulting cleartext message if the message is authentic.
        public mutating func open<C: DataProtocol, AD: DataProtocol>(_ ciphertext: C, authenticating aad: AD) throws -> Data {
            return try context.keySchedule.open(ciphertext, authenticating: aad)
        }
        
        /// Decrypts a message, if the ciphertext is valid.
        ///
        /// You can call this method multiple times to decrypt a series of messages.
        /// When using this method, the recipient of the ciphertext messages needs to decrypt
        /// them in the same order that the sender encrypts them.
        ///
        /// - Parameters:
        ///   - ciphertext: The ciphertext message to decrypt.
        /// - Note: The system throws errors from ``CryptoKit/HPKE/Errors`` when it encounters them.
        /// - Returns: The resulting cleartext message if the message is authentic.
        public mutating func open<C: DataProtocol>(_ ciphertext: C) throws -> Data {
            return try context.keySchedule.open(ciphertext, authenticating: Data())
        }
    }
}

#endif // Linux or !SwiftPM
