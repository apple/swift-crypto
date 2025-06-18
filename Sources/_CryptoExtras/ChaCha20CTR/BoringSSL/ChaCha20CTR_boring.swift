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

@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims
import Crypto
import CryptoBoringWrapper

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
enum OpenSSLChaCha20CTRImpl {
    static func encrypt<M: DataProtocol, N: ContiguousBytes>(
        key: SymmetricKey,
        message: M,
        counter: UInt32,
        nonce: N
    ) throws -> Data {
        guard key.bitCount == Insecure.ChaCha20CTR.keyBitsCount else {
            throw CryptoKitError.incorrectKeySize
        }

        // If our message, conforming to DataProtocol, happens to be allocated contiguously in memory, then we can grab the first, and only, contiguous region and operate on it
        if message.regions.count == 1 {
            return self._encryptContiguous(
                key: key,
                message: message.regions.first!,
                counter: counter,
                nonce: nonce
            )
        } else {
            // Otherwise we need to consolidate the noncontiguous bytes by instantiating an Array<UInt8>
            let contiguousMessage = Array(message)
            return self._encryptContiguous(
                key: key,
                message: contiguousMessage,
                counter: counter,
                nonce: nonce
            )
        }
    }

    /// A fast-path for encrypting contiguous data. Also inlinable to gain specialization information.
    @inlinable
    static func _encryptContiguous<Plaintext: ContiguousBytes, Nonce: ContiguousBytes>(
        key: SymmetricKey,
        message: Plaintext,
        counter: UInt32,
        nonce: Nonce
    ) -> Data {
        key.withUnsafeBytes { keyPtr in
            nonce.withUnsafeBytes { noncePtr in
                message.withUnsafeBytes { plaintextPtr in
                    // We bind all three pointers here. These binds are not technically safe, but because we
                    // know the pointers don't persist they can't violate the aliasing rules. We really
                    // want a "with memory rebound" function but we don't have it yet.
                    let keyBytes = keyPtr.bindMemory(to: UInt8.self)
                    let nonceBytes = noncePtr.bindMemory(to: UInt8.self)
                    let plaintext = plaintextPtr.bindMemory(to: UInt8.self)

                    var ciphertext = Data(repeating: 0, count: plaintext.count)

                    ciphertext.withUnsafeMutableBytes { ciphertext in
                        CCryptoBoringSSL_CRYPTO_chacha_20(
                            ciphertext.baseAddress,
                            plaintext.baseAddress,
                            plaintext.count,
                            keyBytes.baseAddress,
                            nonceBytes.baseAddress,
                            counter
                        )
                    }

                    return ciphertext
                }
            }
        }
    }
}
