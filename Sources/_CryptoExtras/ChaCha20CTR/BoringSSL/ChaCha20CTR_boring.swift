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
    static func encrypt<M: DataProtocol, N: DataProtocol>(key: SymmetricKey, message: M, counter: UInt32, nonce: N) throws -> [UInt8] {
        guard key.bitCount == Insecure.ChaCha20CTR.keyBitsCount else {
            throw CryptoKitError.incorrectKeySize
        }
        guard nonce.count == Insecure.ChaCha20CTR.nonceByteCount else {
            throw CryptoKitError.incorrectParameterSize
        }

        let plaintext = Array(message)
        var ciphertext = Array<UInt8>(repeating: 0, count: plaintext.count)
        let nonce = Array<UInt8>(nonce)

        self.chacha20CTR(out: &ciphertext, plaintext: plaintext, inLen: plaintext.count, key: key.withUnsafeBytes { Array($0) }, nonce: nonce, counter: counter)

        return ciphertext
    }

    static func chacha20CTR(out: UnsafeMutablePointer<UInt8>, plaintext: UnsafePointer<UInt8>, inLen: Int, key: UnsafePointer<UInt8>, nonce: UnsafePointer<UInt8>, counter: UInt32) {
        let outPtr = UnsafeMutableRawPointer(out).assumingMemoryBound(to: UInt8.self)
        let inPtr = UnsafeRawPointer(plaintext).assumingMemoryBound(to: UInt8.self)
        let keyPtr = UnsafeRawPointer(key).assumingMemoryBound(to: UInt8.self)
        let noncePtr = UnsafeRawPointer(nonce).assumingMemoryBound(to: UInt8.self)

        CCryptoBoringSSL_CRYPTO_chacha_20(
            outPtr,
            inPtr,
            inLen,
            keyPtr,
            noncePtr,
            counter
        )
    }
}
