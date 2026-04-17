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

@_implementationOnly import CCryptoBoringSSL
import Crypto

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
enum OpenSSLAESCFBImpl {
    @usableFromInline
    enum Mode {
        case encrypt
        case decrypt

        @usableFromInline
        var _boringSSLParameter: Int32 {
            switch self {
            case .encrypt: return AES_ENCRYPT
            case .decrypt: return AES_DECRYPT
            }
        }
    }

    @inlinable
    static func encryptOrDecrypt<Plaintext: ContiguousBytes>(
        _ mode: Mode,
        _ plaintext: Plaintext,
        using key: SymmetricKey,
        iv: AES._CFB.IV
    ) throws -> Data {
        guard [128, 192, 256].contains(key.bitCount) else {
            throw CryptoKitError.incorrectKeySize
        }
        return plaintext.withUnsafeBytes { plaintextBufferPtr in
            Self._encryptOrDecrypt(mode, plaintextBufferPtr, using: key, iv: iv)
        }
    }

    @usableFromInline
    static func _encryptOrDecrypt(
        _ mode: Mode,
        _ plaintextBufferPtr: UnsafeRawBufferPointer,
        using key: SymmetricKey,
        iv: AES._CFB.IV
    ) -> Data {
        var ciphertext = Data(repeating: 0, count: plaintextBufferPtr.count)
        ciphertext.withUnsafeMutableBytes { ciphertextBufferPtr in
            var iv = iv
            var num = UInt32.zero
            key.withUnsafeBytes { keyBufferPtr in
                iv.withUnsafeMutableBytes { ivBufferPtr in
                    var key = AES_KEY()
                    precondition(
                        CCryptoBoringSSL_AES_set_encrypt_key(
                            keyBufferPtr.baseAddress,
                            UInt32(keyBufferPtr.count * 8),
                            &key
                        ) == 0
                    )
                    CCryptoBoringSSL_AES_cfb128_encrypt(
                        plaintextBufferPtr.baseAddress,
                        ciphertextBufferPtr.baseAddress,
                        plaintextBufferPtr.count,
                        &key,
                        ivBufferPtr.baseAddress,
                        &num,
                        mode._boringSSLParameter
                    )
                }
            }
        }
        return ciphertext
    }
}
