//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftCrypto project authors
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

enum OpenSSLChaCha20CTRImpl {
    static func encrypt<M: DataProtocol, N: ContiguousBytes>(key: SymmetricKey, message: M, counter: UInt32, nonce: N) throws -> Data {
        guard key.bitCount == Insecure.ChaCha20CTR.keyBitsCount else {
            throw CryptoKitError.incorrectKeySize
        }

        var ciphertext = Array<UInt8>(repeating: 0, count: message.count)

        key.withUnsafeBytes { keyPointer in
            message.withContiguousStorageIfAvailable { plaintext in
                nonce.withUnsafeBytes { noncePointer in
                    self.chacha20CTR(out: &ciphertext, plaintext: plaintext, inLen: plaintext.count, key: keyPointer.bindMemory(to: UInt8.self), nonce: noncePointer.bindMemory(to: UInt8.self), counter: counter)
                }
            }
        }

        return Data(ciphertext)
    }

    static func chacha20CTR(out: UnsafeMutablePointer<UInt8>, plaintext: UnsafeBufferPointer<UInt8>, inLen: Int, key: UnsafeBufferPointer<UInt8>, nonce: UnsafeBufferPointer<UInt8>, counter: UInt32) {
        CCryptoBoringSSL_CRYPTO_chacha_20(
            out,
            plaintext.baseAddress,
            inLen,
            key.baseAddress,
            nonce.baseAddress,
            counter
        )
    }
}
