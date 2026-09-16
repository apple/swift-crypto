//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AES {
    /// The Advanced Encryption Standard (AES) Cipher Block Chaining (CBC) cipher
    /// suite.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum _CBC {
        /// Encrypts data using AES-CBC.
        ///
        /// - Parameters:
        ///   - plaintext: The message to encrypt.
        ///   - key: A encryption key.
        ///   - iv: The initialization vector.
        /// - Returns: The encrypted ciphertext.
        public static func encrypt<Plaintext: DataProtocol>(_ plaintext: Plaintext, using key: SymmetricKey, iv: AES._CBC.IV) throws -> Data {
            try self.encrypt(plaintext, using: key, iv: iv, noPadding: false)
        }
        
        /// Encrypts data using AES-CBC.
        ///
        /// - Parameters:
        ///   - plaintext: The message to encrypt.
        ///   - key: A encryption key.
        ///   - iv: The initialization vector.
        ///   - noPadding: If set to `true`, padding won't be added.
        /// - Returns: The encrypted ciphertext.
        ///
        /// - Note: If `noPadding` is set to `true`, `plainText` has to be a multiple of the blockSize (16 bytes). Otherwise an error will be thrown.
        public static func encrypt<Plaintext: DataProtocol>(_ plaintext: Plaintext, using key: SymmetricKey, iv: AES._CBC.IV, noPadding: Bool) throws -> Data {
            try OpenSSLAESCBCImpl.encrypt(plaintext, using: key, iv: iv, noPadding: noPadding)
        }

        /// Decrypts data using AES-CBC.
        ///
        /// - Parameters:
        ///   - ciphertext: The encrypted ciphertext.
        ///   - key: A decryption key.
        ///   - iv: The initialization vector.
        /// - Returns: The decrypted message.
        public static func decrypt<Ciphertext: DataProtocol>(_ ciphertext: Ciphertext, using key: SymmetricKey, iv: AES._CBC.IV) throws -> Data {
            try self.decrypt(ciphertext, using: key, iv: iv, noPadding: false)
        }
        
        /// Decrypts data using AES-CBC.
        ///
        /// - Parameters:
        ///   - ciphertext: The encrypted ciphertext.
        ///   - key: A decryption key.
        ///   - iv: The initialization vector.
        ///   - noPadding: If this is set to `true`, padding won't be removed.
        /// - Returns: The decrypted message.
        public static func decrypt<Ciphertext: DataProtocol>(_ ciphertext: Ciphertext, using key: SymmetricKey, iv: AES._CBC.IV, noPadding: Bool) throws -> Data {
            try OpenSSLAESCBCImpl.decrypt(ciphertext, using: key, iv: iv, noPadding: noPadding)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AES._CBC {
    /// An initialization vector.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public struct IV: Sendable, Sequence {
        // AES CBC uses a 128-bit IV.
        @usableFromInline
        var ivBytes: (
            UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
            UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8
        )

        public init() {
            var rng = SystemRandomNumberGenerator()
            let (first, second) = (rng.next(), rng.next())

            self.ivBytes = (
                UInt8(truncatingIfNeeded: first),
                UInt8(truncatingIfNeeded: first >> 8),
                UInt8(truncatingIfNeeded: first >> 16),
                UInt8(truncatingIfNeeded: first >> 24),
                UInt8(truncatingIfNeeded: first >> 32),
                UInt8(truncatingIfNeeded: first >> 40),
                UInt8(truncatingIfNeeded: first >> 48),
                UInt8(truncatingIfNeeded: first >> 56),
                UInt8(truncatingIfNeeded: second),
                UInt8(truncatingIfNeeded: second >> 8),
                UInt8(truncatingIfNeeded: second >> 16),
                UInt8(truncatingIfNeeded: second >> 24),
                UInt8(truncatingIfNeeded: second >> 32),
                UInt8(truncatingIfNeeded: second >> 40),
                UInt8(truncatingIfNeeded: second >> 48),
                UInt8(truncatingIfNeeded: second >> 56)
            )
        }

        public init<IVBytes: Collection>(ivBytes: IVBytes) throws where IVBytes.Element == UInt8 {
            // We support a 128-bit IV.
            guard ivBytes.count == 16 else {
                throw CryptoKitError.incorrectKeySize
            }

            self.ivBytes = (
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0
            )

            Swift.withUnsafeMutableBytes(of: &self.ivBytes) { bytesPtr in
                bytesPtr.copyBytes(from: ivBytes)
            }
        }
        
        @inlinable
        public func makeIterator() -> some IteratorProtocol<UInt8> {
            withUnsafeBytes(of: ivBytes) { unsafeRawBufferPointer in
                Array(unsafeRawBufferPointer).makeIterator()
            }
        }

        mutating func withUnsafeMutableBytes<ReturnType>(_ body: (UnsafeMutableRawBufferPointer) throws -> ReturnType) rethrows -> ReturnType {
            return try Swift.withUnsafeMutableBytes(of: &self.ivBytes, body)
        }

    }
}
