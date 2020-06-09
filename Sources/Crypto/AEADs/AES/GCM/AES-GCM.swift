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
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
typealias AESGCMImpl = CoreCryptoGCMImpl
import Security
#else
typealias AESGCMImpl = OpenSSLAESGCMImpl
#endif

import Foundation

extension AES {
    /// AES in GCM mode with 128-bit tags.
    public enum GCM: Cipher {
        static let tagByteCount = 16
        static let defaultNonceByteCount = 12
        
        /// Encrypts and authenticates data using AES-GCM.
        ///
        /// - Parameters:
        ///   - message: The message to encrypt and authenticate
        ///   - key: An encryption key of 128, 192 or 256 bits
        ///   - nonce: An Nonce for AES-GCM encryption. The nonce must be unique for every use of the key to seal data. It can be safely generated with AES.GCM.Nonce()
        ///   - authenticatedData: Data to authenticate as part of the seal
        /// - Returns: A sealed box returning the authentication tag (seal) and the ciphertext
        /// - Throws: CipherError errors
        public static func seal<Plaintext: DataProtocol, AuthenticatedData: DataProtocol>
            (_ message: Plaintext, using key: SymmetricKey, nonce: Nonce? = nil, authenticating authenticatedData: AuthenticatedData) throws -> SealedBox {
            return try AESGCMImpl.seal(key: key, message: message, nonce: nonce, authenticatedData: authenticatedData)
        }

        /// Encrypts and authenticates data using AES-GCM.
        ///
        /// - Parameters:
        ///   - message: The message to encrypt and authenticate
        ///   - key: An encryption key of 128, 192 or 256 bits
        ///   - nonce: An Nonce for AES-GCM encryption. The nonce must be unique for every use of the key to seal data. It can be safely generated with AES.GCM.Nonce()
        /// - Returns: A sealed box returning the authentication tag (seal) and the ciphertext
        /// - Throws: CipherError errors
        public static func seal<Plaintext: DataProtocol>
            (_ message: Plaintext, using key: SymmetricKey, nonce: Nonce? = nil) throws -> SealedBox {
            return try AESGCMImpl.seal(key: key, message: message, nonce: nonce, authenticatedData: Data?.none)
        }

        /// Authenticates and decrypts data using AES-GCM.
        ///
        /// - Parameters:
        ///   - sealedBox: The sealed box to authenticate and decrypt
        ///   - key: An encryption key of 128, 192 or 256 bits
        ///   - nonce: An Nonce for AES-GCM encryption. The nonce must be unique for every use of the key to seal data. It can be safely generated with AES.GCM.Nonce().
        ///   - authenticatedData:  Data that was authenticated as part of the seal
        /// - Returns: The ciphertext if opening was successful
        /// - Throws: CipherError errors. If the authentication of the sealedbox failed, incorrectTag is thrown.
        public static func open<AuthenticatedData: DataProtocol>
            (_ sealedBox: SealedBox, using key: SymmetricKey, authenticating authenticatedData: AuthenticatedData) throws -> Data {
            return try AESGCMImpl.open(key: key, sealedBox: sealedBox, authenticatedData: authenticatedData)
        }

        /// Authenticates and decrypts data using AES-GCM.
        ///
        /// - Parameters:
        ///   - sealedBox: The sealed box to authenticate and decrypt
        ///   - key: An encryption key of 128, 192 or 256 bits
        ///   - nonce: An Nonce for AES-GCM encryption. The nonce must be unique for every use of the key to seal data. It can be safely generated with AES.GCM.Nonce().
        /// - Returns: The ciphertext if opening was successful
        /// - Throws: CipherError errors. If the authentication of the sealedbox failed, incorrectTag is thrown.
        public static func open(_ sealedBox: SealedBox, using key: SymmetricKey) throws -> Data {
            return try AESGCMImpl.open(key: key, sealedBox: sealedBox, authenticatedData: Data?.none)
        }
    }
}

extension AES.GCM {
    public struct SealedBox: AEADSealedBox {
        private let combinedRepresentation: Data
        private let nonceByteCount: Int
        
        /// The authentication tag
        public var tag: Data {
            return combinedRepresentation.suffix(AES.GCM.tagByteCount)
        }
        /// The ciphertext
        public var ciphertext: Data {
            return combinedRepresentation.dropFirst(nonceByteCount).dropLast(AES.GCM.tagByteCount)
        }
        /// The Nonce
        public var nonce: AES.GCM.Nonce {
            return try! AES.GCM.Nonce(data: combinedRepresentation.prefix(nonceByteCount))
        }
        
        /// The combined representation ( nonce || ciphertext || tag)
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
        
        @inlinable
        public init<D: DataProtocol>(combined: D) throws {
            // AES minimum nonce (12 bytes) + AES tag (16 bytes)
            // While we have these values in the internal APIs, we can't use it in inlinable code.
            let aesGCMOverhead = 12 + 16
            
            if combined.count < aesGCMOverhead {
                throw CryptoKitError.incorrectParameterSize
            }
            
            self.init(combined: Data(combined))
        }
        
        public init<C: DataProtocol, T: DataProtocol>(nonce: AES.GCM.Nonce, ciphertext: C, tag: T) throws {
            guard tag.count == AES.GCM.tagByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }
            
            self.combinedRepresentation = nonce.bytes + ciphertext + tag
            self.nonceByteCount = nonce.bytes.count
        }
        
    }
}
#endif  // Linux or !SwiftPM
