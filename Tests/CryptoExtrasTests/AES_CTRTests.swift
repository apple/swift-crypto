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
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
@testable import CryptoExtras
import XCTest

final class AESCTRTests: XCTestCase {
    /// This plaintext is the plaintext for the NIST test vectors from
    /// NIST Special Publication 800-38A.
    static let plaintext = """
    6bc1bee22e409f96e93d7e117393172a\
    ae2d8a571e03ac9c9eb76fac45af8e51\
    30c81c46a35ce411e5fbc1191a0a52ef\
    f69f2445df4f9b17ad2b417be66c3710
    """

    static let plaintextBytes: Data = try! Data(Array(hexString: plaintext))

    func testEncryptionVectorF51() throws {
        let hexKey = "2b7e151628aed2a6abf7158809cf4f3c"
        let key = SymmetricKey(hexEncoded: hexKey)

        let hexNonce = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        let nonce = try AES._CTR.Nonce(nonceBytes: Array(hexString: hexNonce))

        let plaintext = Self.plaintextBytes
        let encryptedBytes = try AES._CTR.encrypt(plaintext, using: key, nonce: nonce)

        let ciphertext = """
        874d6191b620e3261bef6864990db6ce\
        9806f66b7970fdff8617187bb9fffdff\
        5ae4df3edbd5d35e5b4f09020db03eab\
        1e031dda2fbe03d1792170a0f3009cee
        """
        let ciphertextBytes = try Data(hexString: ciphertext)
        XCTAssertEqual(encryptedBytes, ciphertextBytes)
    }

    func testDecryptionVectorF52() throws {
        let hexKey = "2b7e151628aed2a6abf7158809cf4f3c"
        let key = SymmetricKey(hexEncoded: hexKey)

        let hexNonce = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        let nonce = try AES._CTR.Nonce(nonceBytes: Array(hexString: hexNonce))

        let ciphertext = """
        874d6191b620e3261bef6864990db6ce\
        9806f66b7970fdff8617187bb9fffdff\
        5ae4df3edbd5d35e5b4f09020db03eab\
        1e031dda2fbe03d1792170a0f3009cee
        """
        let ciphertextBytes = try Array(hexString: ciphertext)
        let decryptedBytes = try AES._CTR.decrypt(ciphertextBytes, using: key, nonce: nonce)
        XCTAssertEqual(Self.plaintextBytes, decryptedBytes)
    }

    func testEncryptionVectorF53() throws {
        let hexKey = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
        let key = SymmetricKey(hexEncoded: hexKey)

        let hexNonce = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        let nonce = try AES._CTR.Nonce(nonceBytes: Array(hexString: hexNonce))

        let plaintext = Self.plaintextBytes
        let encryptedBytes = try AES._CTR.encrypt(plaintext, using: key, nonce: nonce)

        let ciphertext = """
        1abc932417521ca24f2b0459fe7e6e0b\
        090339ec0aa6faefd5ccc2c6f4ce8e94\
        1e36b26bd1ebc670d1bd1d665620abf7\
        4f78a7f6d29809585a97daec58c6b050
        """
        let ciphertextBytes = try Data(hexString: ciphertext)
        XCTAssertEqual(encryptedBytes, ciphertextBytes)
    }

    func testDecryptionVectorF54() throws {
        let hexKey = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
        let key = SymmetricKey(hexEncoded: hexKey)

        let hexNonce = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        let nonce = try AES._CTR.Nonce(nonceBytes: Array(hexString: hexNonce))

        let ciphertext = """
        1abc932417521ca24f2b0459fe7e6e0b\
        090339ec0aa6faefd5ccc2c6f4ce8e94\
        1e36b26bd1ebc670d1bd1d665620abf7\
        4f78a7f6d29809585a97daec58c6b050
        """
        let ciphertextBytes = try Array(hexString: ciphertext)
        let decryptedBytes = try AES._CTR.decrypt(ciphertextBytes, using: key, nonce: nonce)
        XCTAssertEqual(Self.plaintextBytes, decryptedBytes)
    }

    func testEncryptionVectorF55() throws {
        let hexKey = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
        let key = SymmetricKey(hexEncoded: hexKey)

        let hexNonce = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        let nonce = try AES._CTR.Nonce(nonceBytes: Array(hexString: hexNonce))

        let plaintext = Self.plaintextBytes
        let encryptedBytes = try AES._CTR.encrypt(plaintext, using: key, nonce: nonce)

        let ciphertext = """
        601ec313775789a5b7a7f504bbf3d228\
        f443e3ca4d62b59aca84e990cacaf5c5\
        2b0930daa23de94ce87017ba2d84988d\
        dfc9c58db67aada613c2dd08457941a6
        """
        let ciphertextBytes = try Data(hexString: ciphertext)
        XCTAssertEqual(encryptedBytes, ciphertextBytes)
    }

    func testDecryptionVectorF56() throws {
        let hexKey = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
        let key = SymmetricKey(hexEncoded: hexKey)

        let hexNonce = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        let nonce = try AES._CTR.Nonce(nonceBytes: Array(hexString: hexNonce))

        let ciphertext = """
        601ec313775789a5b7a7f504bbf3d228\
        f443e3ca4d62b59aca84e990cacaf5c5\
        2b0930daa23de94ce87017ba2d84988d\
        dfc9c58db67aada613c2dd08457941a6
        """
        let ciphertextBytes = try Array(hexString: ciphertext)
        let decryptedBytes = try AES._CTR.decrypt(ciphertextBytes, using: key, nonce: nonce)
        XCTAssertEqual(Self.plaintextBytes, decryptedBytes)
    }

    func testRejectsInvalidNonceSizes() throws {
        let someBytes = Array(repeating: UInt8(0), count: 24)

        for count in 0..<someBytes.count {
            let nonceBytes = someBytes.prefix(count)

            if count != 12 && count != 16 {
                XCTAssertThrowsError(try AES._CTR.Nonce(nonceBytes: nonceBytes))
            } else {
                XCTAssertNoThrow(try AES._CTR.Nonce(nonceBytes: nonceBytes))
            }
        }
    }
}
