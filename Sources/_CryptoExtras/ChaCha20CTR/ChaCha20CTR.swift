//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims
import Crypto
@_implementationOnly import CryptoBoringWrapper
import Foundation

typealias ChaCha20CTRImpl = OpenSSLChaCha20CTRImpl

extension Insecure {
    /// ChaCha20-CTR with 96-bit nonces and a 32 bit counter.
    public enum ChaCha20CTR {
        static let keyBitsCount = 256
        static let nonceByteCount = 12
        static let counterByteCount = 4

        /// Encrypts data using ChaCha20CTR
        ///
        /// - Parameters:
        ///   - message: The message to encrypt
        ///   - key: A 256-bit encryption key
        ///   - counter: A 4 byte counter (UInt32), defaults to 0
        ///   - nonce: A 12 byte nonce for ChaCha20 encryption. The nonce must be unique for every use of the key to seal data.
        /// - Returns: The encrypted ciphertext
        /// - Throws: CipherError errors
        /// - Warning: You most likely want to use the ChaChaPoly implemention with AuthenticatedData available at `Crypto.ChaChaPoly`
        public static func encrypt<Plaintext: DataProtocol, Nonce: DataProtocol>
        (_ message: Plaintext, using key: SymmetricKey, counter: UInt32 = 0, nonce: Nonce) throws -> [UInt8] {
            return try ChaCha20CTRImpl.encrypt(key: key, message: message, counter: counter, nonce: nonce)
        }
    }
}
