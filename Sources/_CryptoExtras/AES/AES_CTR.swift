//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import Foundation

@usableFromInline
typealias AESCTRImpl = OpenSSLAESCTRImpl

extension AES {
    public enum _CTR {
        static let nonceByteCount = 12
      
        @inlinable
        public static func encrypt<Plaintext: DataProtocol>(
            _ plaintext: Plaintext,
            using key: SymmetricKey,
            nonce: AES._CTR.Nonce
        ) throws -> Data {
            let bytes: ContiguousBytes = plaintext.regions.count == 1 ? plaintext.regions.first! : Array(plaintext)
            return try AESCTRImpl.encrypt(bytes, using: key, nonce: nonce)
        }

        @inlinable
        public static func decrypt<Ciphertext: DataProtocol>(
            _ ciphertext: Ciphertext,
            using key: SymmetricKey,
            nonce: AES._CTR.Nonce
        ) throws -> Data {
            // Surprise, CTR mode is symmetric in encryption/decryption!
            try Self.encrypt(ciphertext, using: key, nonce: nonce)
        }
    }
}
