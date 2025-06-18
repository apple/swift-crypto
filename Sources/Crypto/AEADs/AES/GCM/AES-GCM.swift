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
#if (!CRYPTO_IN_SWIFTPM_FORCE_BUILD_API) || CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias AESGCMImpl = CoreCryptoGCMImpl
#else
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias AESGCMImpl = OpenSSLAESGCMImpl
#endif

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
extension AES {
    /// The Advanced Encryption Standard (AES) Galois Counter Mode (GCM) cipher
    /// suite.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum GCM: Cipher, Sendable {
        static let tagByteCount = 16
        static let defaultNonceByteCount = 12
        
        /// Secures the given plaintext message with encryption and an
        /// authentication tag that covers both the encrypted data and
        /// additional data.
        ///
        /// - Parameters:
        ///   - message: The plaintext data to seal.
        ///   - key: A cryptographic key used to seal the message.
        ///   - nonce: The nonce the sealing process requires. If you don't provide a nonce, the method generates a random one by invoking ``AES/GCM/Nonce/init()``.
        ///   - authenticatedData: Additional data to be authenticated.
        ///
        /// - Returns: The sealed message.
        public static func seal<Plaintext: DataProtocol, AuthenticatedData: DataProtocol>
            (_ message: Plaintext, using key: SymmetricKey, nonce: Nonce? = nil, authenticating authenticatedData: AuthenticatedData) throws(CryptoKitMetaError) -> SealedBox {
            return try AESGCMImpl.seal(key: key, message: message, nonce: nonce, authenticatedData: authenticatedData)
        }

        /// Secures the given plaintext message with encryption and an
        /// authentication tag.
        ///
        /// - Parameters:
        ///   - message: The plaintext data to seal.
        ///   - key: A cryptographic key used to seal the message.
        ///   - nonce: The nonce the sealing process requires. If you don't provide a nonce, the method generates a random one by invoking ``AES/GCM/Nonce/init()``.
        ///
        /// - Returns: The sealed message.
        public static func seal<Plaintext: DataProtocol>
            (_ message: Plaintext, using key: SymmetricKey, nonce: Nonce? = nil) throws(CryptoKitMetaError) -> SealedBox {
            return try AESGCMImpl.seal(key: key, message: message, nonce: nonce, authenticatedData: Data?.none)
        }

        /// Decrypts the message and verifies the authenticity of both the
        /// encrypted message and additional data.
        ///
        /// - Parameters:
        ///   - sealedBox: The sealed box to open.
        ///   - key: The cryptographic key that was used to seal the message.
        ///   - authenticatedData: Additional data that was authenticated.
        ///
        /// - Returns: The original plaintext message that was sealed in the
        /// box, as long as the correct key is used and authentication succeeds.
        /// The call throws an error if decryption or authentication fail.
        public static func open<AuthenticatedData: DataProtocol>
            (_ sealedBox: SealedBox, using key: SymmetricKey, authenticating authenticatedData: AuthenticatedData) throws(CryptoKitMetaError) -> Data {
            return try AESGCMImpl.open(key: key, sealedBox: sealedBox, authenticatedData: authenticatedData)
        }

        /// Decrypts the message and verifies its authenticity.
        ///
        /// - Parameters:
        ///   - sealedBox: The sealed box to open.
        ///   - key: The cryptographic key that was used to seal the message.
        ///
        /// - Returns: The original plaintext message that was sealed in the
        /// box, as long as the correct key is used and authentication succeeds.
        /// The call throws an error if decryption or authentication fail.
        public static func open(_ sealedBox: SealedBox, using key: SymmetricKey) throws(CryptoKitMetaError) -> Data {
            return try AESGCMImpl.open(key: key, sealedBox: sealedBox, authenticatedData: Data?.none)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AES.GCM {
    /// A secure container for your data that you can access using a cipher.
    ///
    /// Use a sealed box as a container for data that you want to transmit
    /// securely. Seal data into a box with one of the cipher algorithms, like
    /// ``seal(_:using:nonce:)``.
    ///
    /// The box holds an encrypted version of the original data, an
    /// authentication tag, and the nonce during encryption. The encryption
    /// makes the data unintelligible to anyone without the key, while the
    /// authentication tag makes it possible for the intended receiver to be
    /// sure the data remains intact.
    ///
    /// The receiver uses another instance of the same cipher, like the
    /// ``open(_:using:)`` method, to open the box.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public struct SealedBox: AEADSealedBox, Sendable {
        private let combinedRepresentation: Data
        private let nonceByteCount: Int
        
        /// An authentication tag.
        ///
        /// The authentication tag has a length of 16 bytes.
        public var tag: Data {
            return combinedRepresentation.suffix(AES.GCM.tagByteCount)
        }
        /// The encrypted data.
        ///
        /// The length of the ciphertext of a sealed box is the same as the
        /// length of the plaintext you encrypt.
        public var ciphertext: Data {
            return combinedRepresentation.dropFirst(nonceByteCount).dropLast(AES.GCM.tagByteCount)
        }
        /// The nonce used to encrypt the data.
        public var nonce: AES.GCM.Nonce {
            return try! AES.GCM.Nonce(data: combinedRepresentation.prefix(nonceByteCount))
        }
        
        /// A combined element composed of the nonce, encrypted data, and
        /// authentication tag.
        ///
        /// The combined representation is only available when the
        /// ``AES/GCM/Nonce`` size is the default size of 12 bytes. The data
        /// layout of the combined representation is nonce, ciphertext, then
        /// tag.
        public var combined: Data? {
            if nonceByteCount == AES.GCM.defaultNonceByteCount {
                return self.combinedRepresentation
            } else {
                return nil
            }
        }
        
        @usableFromInline
        internal init(combined: Data) {
            self.combinedRepresentation = combined
            self.nonceByteCount = AES.GCM.defaultNonceByteCount
        }

        internal init(combined: Data, nonceByteCount: Int) {
            self.combinedRepresentation = combined
            self.nonceByteCount = nonceByteCount
        }
        
        /// Creates a sealed box from the combined bytes of an authentication
        /// tag, nonce, and encrypted data.
        ///
        /// - Parameters:
        ///   - combined: The combined bytes of the nonce, encrypted data, and
        /// authentication tag.
        @inlinable
        public init<D: DataProtocol>(combined: D) throws(CryptoKitMetaError) {
            // AES minimum nonce (12 bytes) + AES tag (16 bytes)
            // While we have these values in the internal APIs, we can't use it in inlinable code.
            let aesGCMOverhead = 12 + 16
            
            if combined.count < aesGCMOverhead {
                #if hasFeature(Embedded)
                throw CryptoKitMetaError.cryptoKitError(underlyingError: CryptoKitError.incorrectParameterSize)
                #else
                throw CryptoKitError.incorrectParameterSize
                #endif
            }
            
            self.init(combined: Data(combined))
        }
        
        /// Creates a sealed box from the given tag, nonce, and ciphertext.
        ///
        /// - Parameters:
        ///   - nonce: The nonce.
        ///   - ciphertext: The encrypted data.
        ///   - tag: The authentication tag.
        public init<C: DataProtocol, T: DataProtocol>(nonce: AES.GCM.Nonce, ciphertext: C, tag: T) throws(CryptoKitMetaError) {
            guard tag.count == AES.GCM.tagByteCount else {
                throw error(CryptoKitError.incorrectParameterSize)
            }

            let nonceByteCount = nonce.bytes.count
            var combinedRepresentation = Data()
            combinedRepresentation.reserveCapacity(nonceByteCount + ciphertext.count + tag.count)
            combinedRepresentation.append(contentsOf: nonce.bytes)
            combinedRepresentation.append(contentsOf: ciphertext)
            combinedRepresentation.append(contentsOf: tag)

            self.init(combined: combinedRepresentation, nonceByteCount: nonceByteCount)
        }
        
    }
}
#endif  // Linux or !SwiftPM
