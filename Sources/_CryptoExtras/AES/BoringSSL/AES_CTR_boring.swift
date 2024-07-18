//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_implementationOnly import CCryptoBoringSSL
import Crypto
import Foundation

@usableFromInline
enum OpenSSLAESCTRImpl {
    @inlinable
    static func encrypt<Plaintext: ContiguousBytes>(
        _ plaintext: Plaintext,
        using key: SymmetricKey,
        nonce: AES._CTR.Nonce
    ) throws -> Data {
        guard [128, 192, 256].contains(key.bitCount) else {
            throw CryptoKitError.incorrectKeySize
        }
        return plaintext.withUnsafeBytes { plaintextBufferPtr in
            Self._encrypt(plaintextBufferPtr, using: key, nonce: nonce)
        }
    }

    @usableFromInline
    static func _encrypt(
        _ plaintextBufferPtr: UnsafeRawBufferPointer,
        using key: SymmetricKey,
        nonce: AES._CTR.Nonce
    ) -> Data {
        var ciphertext = Data(repeating: 0, count: plaintextBufferPtr.count)
        ciphertext.withUnsafeMutableBytes { ciphertextBufferPtr in
            var nonce = nonce
            var ecountBytes = (Int64.zero, Int64.zero)
            var num = UInt32.zero
            key.withUnsafeBytes { keyBufferPtr in
                nonce.withUnsafeMutableBytes { nonceBufferPtr in
                    withUnsafeMutableBytes(of: &ecountBytes) { ecountBufferPtr in
                        var key = AES_KEY()
                        precondition(CCryptoBoringSSL_AES_set_encrypt_key(keyBufferPtr.baseAddress, UInt32(keyBufferPtr.count * 8), &key) == 0)
                        CCryptoBoringSSL_AES_ctr128_encrypt(
                            plaintextBufferPtr.baseAddress,
                            ciphertextBufferPtr.baseAddress,
                            plaintextBufferPtr.count,
                            &key,
                            nonceBufferPtr.baseAddress,
                            ecountBufferPtr.baseAddress,
                            &num
                        )
                    }
                }
            }
        }
        return ciphertext
    }
}
