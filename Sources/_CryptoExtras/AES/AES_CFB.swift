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
typealias AESCFBImpl = OpenSSLAESCFBImpl

extension AES {
    public enum _CFB {
        static let nonceByteCount = 16
      
        @inlinable
        public static func encrypt<Plaintext: DataProtocol>(
            _ plaintext: Plaintext,
            using key: SymmetricKey,
            iv: AES._CFB.IV
        ) throws -> Data {
            let bytes: ContiguousBytes = plaintext.regions.count == 1 ? plaintext.regions.first! : Array(plaintext)
            return try AESCFBImpl.encryptOrDecrypt(.encrypt, bytes, using: key, iv: iv)
        }

        @inlinable
        public static func decrypt<Ciphertext: DataProtocol>(
            _ ciphertext: Ciphertext,
            using key: SymmetricKey,
            iv: AES._CFB.IV
        ) throws -> Data {
            let bytes: ContiguousBytes = ciphertext.regions.count == 1 ? ciphertext.regions.first! : Array(ciphertext)
            return try AESCFBImpl.encryptOrDecrypt(.decrypt, bytes, using: key, iv: iv)
        }
    }
}
