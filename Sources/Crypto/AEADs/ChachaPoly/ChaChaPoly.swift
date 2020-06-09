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
typealias ChaChaPolyImpl = CoreCryptoChaChaPolyImpl
import Security
#else
typealias ChaChaPolyImpl = OpenSSLChaChaPolyImpl
#endif

import Foundation

/// ChaCha20-Poly1305 as described in RFC 7539 with 96-bit nonces.
public enum ChaChaPoly: Cipher {
    static let tagByteCount = 16
    static let keyBitsCount = 256
    static let nonceByteCount = 12

    /// Encrypts and seals data using ChaCha20-Poly1305.
    ///
    /// - Parameters:
    ///   - message: The message to encrypt and authenticate
    ///   - key: A 256-bit encryption key
    ///   - nonce: A nonce for ChaChaPoly encryption. The nonce must be unique for every use of the key to seal data. It can be safely generated with ChaChaPoly.Nonce()
    ///   - authenticatedData: Data to authenticate as part of the seal
    /// - Returns: A sealed box returning the authentication tag (seal) and the ciphertext
    /// - Throws: CipherError errors
    public static func seal<Plaintext: DataProtocol, AuthenticatedData: DataProtocol>
        (_ message: Plaintext, using key: SymmetricKey, nonce: Nonce? = nil, authenticating authenticatedData: AuthenticatedData) throws -> SealedBox {
        return try ChaChaPolyImpl.encrypt(key: key, message: message, nonce: nonce, authenticatedData: authenticatedData)
    }

    /// Encrypts and seals data using ChaCha20-Poly1305.
    ///
    /// - Parameters:
    ///   - message: The message to encrypt and authenticate
    ///   - key: A 256-bit encryption key
    ///   - nonce: A nonce for ChaChaPoly encryption. The nonce must be unique for every use of the key to seal data. It can be safely generated with ChaChaPoly.Nonce()
    /// - Returns: A sealed box returning the authentication tag (seal) and the ciphertext
    /// - Throws: CipherError errors
    public static func seal<Plaintext: DataProtocol>
        (_ message: Plaintext, using key: SymmetricKey, nonce: Nonce? = nil) throws -> SealedBox {
        return try ChaChaPolyImpl.encrypt(key: key, message: message, nonce: nonce, authenticatedData: Data?.none)
    }

    /// Authenticates and decrypts data using ChaCha20-Poly1305.
    ///
    /// - Parameters:
    ///   - sealedBox: The sealed box to authenticate and decrypt
    ///   - key: A 256-bit encryption key
    ///   - nonce: The nonce that was provided for encryption.
    ///   - authenticatedData:  Data that was authenticated as part of the seal
    /// - Returns: The ciphertext if opening was successful
    /// - Throws: CipherError errors. If the authentication of the sealedbox failed, incorrectTag is thrown.
    public static func open<AuthenticatedData: DataProtocol>
        (_ sealedBox: SealedBox, using key: SymmetricKey, authenticating authenticatedData: AuthenticatedData) throws -> Data {
        return try ChaChaPolyImpl.decrypt(key: key, ciphertext: sealedBox, authenticatedData: authenticatedData)
    }

    /// Authenticates and decrypts data using ChaCha20-Poly1305.
    ///
    /// - Parameters:
    ///   - sealedBox: The sealed box to authenticate and decrypt
    ///   - key: A 256-bit encryption key
    ///   - nonce: The nonce that was provided for encryption.
    /// - Returns: The ciphertext if opening was successful
    /// - Throws: CipherError errors. If the authentication of the sealedbox failed, incorrectTag is thrown.
    public static func open
        (_ sealedBox: SealedBox, using key: SymmetricKey) throws -> Data {
        return try ChaChaPolyImpl.decrypt(key: key, ciphertext: sealedBox, authenticatedData: Data?.none)
    }
}

extension ChaChaPoly {
    @frozen
    public struct SealedBox: AEADSealedBox {
        /// The combined representation ( nonce || ciphertext || tag)
        public let combined: Data
        /// The authentication tag
        public var tag: Data {
            return combined.suffix(ChaChaPoly.tagByteCount)
        }
        /// The ciphertext
        public var ciphertext: Data {
            return combined.dropFirst(ChaChaPoly.nonceByteCount).dropLast(ChaChaPoly.tagByteCount)
        }
        /// The Nonce
        public var nonce: ChaChaPoly.Nonce {
            return try! ChaChaPoly.Nonce(data: combined.prefix(ChaChaPoly.nonceByteCount))
        }
        
        @inlinable
        public init<D: DataProtocol>(combined: D) throws {
            // ChachaPoly nonce (12 bytes) + ChachaPoly tag (16 bytes)
            // While we have these values in the internal APIs, we can't use it in inlinable code.
            let chachaPolyOverhead = 12 + 16
            
            if combined.count < chachaPolyOverhead {
                throw CryptoKitError.incorrectParameterSize
            }
            
            self.combined = Data(combined)
        }
        
        public init<C: DataProtocol, T: DataProtocol>(nonce: ChaChaPoly.Nonce, ciphertext: C, tag: T) throws {
            guard tag.count == ChaChaPoly.tagByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }
            
            self.combined = Data(nonce) + ciphertext + tag
        }
    }
}
#endif // Linux or !SwiftPM
