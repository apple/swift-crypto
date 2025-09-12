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
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import XCTest
import Crypto
import CryptoExtras

class ChaCha20CTRTests: XCTestCase {

    /// Test Vector - https://datatracker.ietf.org/doc/html/rfc9001#name-chacha20-poly1305-short-hea
    func testChaCha20CTR_v1() throws {
        let hpKey = try Array(hexString: "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
        /// Sample = 0x5e5cd55c41f69080575d7999c25a5bfb
        let counterAsData = try Array(hexString: "5e5cd55c")
        let counterAsUInt32 = UInt32(bigEndian: 0x5e5cd55c)
        let iv = try Array(hexString: "41f69080575d7999c25a5bfb")

        let mask: Data = try Insecure.ChaCha20CTR.encrypt(Array<UInt8>(repeating: 0, count: 5), using: SymmetricKey(data: hpKey), counter: Insecure.ChaCha20CTR.Counter(data: counterAsData), nonce: Insecure.ChaCha20CTR.Nonce(data: iv))
        let mask2: Data = try Insecure.ChaCha20CTR.encrypt(Array<UInt8>(repeating: 0, count: 5), using: SymmetricKey(data: hpKey), counter: Insecure.ChaCha20CTR.Counter(offset: counterAsUInt32), nonce: Insecure.ChaCha20CTR.Nonce(data: iv))

        XCTAssertEqual(mask, try Data(hexString: "aefefe7d03"))
        XCTAssertEqual(mask, mask2)
    }

    /// Test Vector - https://www.ietf.org/archive/id/draft-ietf-quic-v2-10.html#name-chacha20-poly1305-short-head
    func testChaCha20CTR_v2() throws {
        let hpKey = try Array(hexString: "d659760d2ba434a226fd37b35c69e2da8211d10c4f12538787d65645d5d1b8e2")
        /// Sample = 0xe7b6b932bc27d786f4bc2bb20f2162ba
        let counterAsData = try Array(hexString: "e7b6b932")
        let counterAsUInt32 = UInt32(bigEndian: 0xe7b6b932)
        let iv = try Array(hexString: "bc27d786f4bc2bb20f2162ba")

        let mask: Data = try Insecure.ChaCha20CTR.encrypt(Array<UInt8>(repeating: 0, count: 5), using: SymmetricKey(data: hpKey), counter: Insecure.ChaCha20CTR.Counter(data: counterAsData), nonce: Insecure.ChaCha20CTR.Nonce(data: iv))
        let mask2: Data = try Insecure.ChaCha20CTR.encrypt(Array<UInt8>(repeating: 0, count: 5), using: SymmetricKey(data: hpKey), counter: Insecure.ChaCha20CTR.Counter(offset: counterAsUInt32), nonce: Insecure.ChaCha20CTR.Nonce(data: iv))

        XCTAssertEqual(mask, try Data(hexString: "97580e32bf"))
        XCTAssertEqual(mask, mask2)
    }

    func testChaCha20CTR_InvalidParameters() throws {
        let keyTooLong: SymmetricKey = SymmetricKey(data: [214, 89, 118, 13, 43, 164, 52, 162, 38, 253, 55, 179, 92, 105, 226, 218, 130, 17, 209, 12, 79, 18, 83, 135, 135, 214, 86, 69, 213, 209, 184, 226, 22])
        XCTAssertThrowsError(try Insecure.ChaCha20CTR.encrypt(Array<UInt8>(repeating: 0, count: 5), using: keyTooLong, nonce: Insecure.ChaCha20CTR.Nonce())) { error in
            guard case CryptoKitError.incorrectKeySize = error else { return XCTFail("Error thrown was of unexpected type: \(error)") }
        }

        let keyTooShort: SymmetricKey = SymmetricKey(data: [214, 89, 118, 13, 43, 164, 52, 162, 38, 253, 55, 179, 92, 105, 226, 218, 130, 17, 209, 12, 79, 18, 83, 135, 135, 214, 86, 69, 213, 209, 184])
        XCTAssertThrowsError(try Insecure.ChaCha20CTR.encrypt(Array<UInt8>(repeating: 0, count: 5), using: keyTooShort, nonce: Insecure.ChaCha20CTR.Nonce())) { error in
            guard case CryptoKitError.incorrectKeySize = error else { return XCTFail("Error thrown was of unexpected type: \(error)") }
        }

        let nonceTooLong: [UInt8] = [188, 39, 215, 134, 244, 188, 43, 178, 15, 33, 98, 186, 14]
        XCTAssertThrowsError(try Insecure.ChaCha20CTR.Nonce(data: nonceTooLong)) { error in
            guard case CryptoKitError.incorrectParameterSize = error else { return XCTFail("Error thrown was of unexpected type: \(error)") }
        }

        let nonceTooShort: [UInt8] = [188, 39, 215, 134, 244, 188, 43, 178, 15, 33, 98]
        XCTAssertThrowsError(try Insecure.ChaCha20CTR.Nonce(data: nonceTooShort)) { error in
            guard case CryptoKitError.incorrectParameterSize = error else { return XCTFail("Error thrown was of unexpected type: \(error)") }
        }

        let counterTooLong: [UInt8] = [231, 182, 185, 50, 82]
        XCTAssertThrowsError(try Insecure.ChaCha20CTR.Counter(data: counterTooLong)) { error in
            guard case CryptoKitError.incorrectParameterSize = error else { return XCTFail("Error thrown was of unexpected type: \(error)") }
        }

        let counterTooShort: [UInt8] = [231, 182, 185]
        XCTAssertThrowsError(try Insecure.ChaCha20CTR.Counter(data: counterTooShort)) { error in
            guard case CryptoKitError.incorrectParameterSize = error else { return XCTFail("Error thrown was of unexpected type: \(error)") }
        }

        let key: SymmetricKey = SymmetricKey(data: [214, 89, 118, 13, 43, 164, 52, 162, 38, 253, 55, 179, 92, 105, 226, 218, 130, 17, 209, 12, 79, 18, 83, 135, 135, 214, 86, 69, 213, 209, 184, 226])

        // Ensure UInt32.max Counter Supported
        XCTAssertNoThrow(try Insecure.ChaCha20CTR.encrypt(Array<UInt8>(repeating: 0, count: 5), using: key, counter: Insecure.ChaCha20CTR.Counter(offset: UInt32.max), nonce: Insecure.ChaCha20CTR.Nonce()))

        // Assert that two calls with the same Counter + Nonce params results in the same output
        let nonce = Insecure.ChaCha20CTR.Nonce()
        let counter = Insecure.ChaCha20CTR.Counter()
        let ciphertext1 = try Insecure.ChaCha20CTR.encrypt(Array<UInt8>(repeating: 0, count: 5), using: key, counter: counter, nonce: nonce)
        let ciphertext2 = try Insecure.ChaCha20CTR.encrypt(Array<UInt8>(repeating: 0, count: 5), using: key, counter: counter, nonce: nonce)
        XCTAssertEqual(ciphertext1, ciphertext2)

        // Assert that two calls with different Nonce params results in different output
        let ciphertext3 = try Insecure.ChaCha20CTR.encrypt(Array<UInt8>(repeating: 0, count: 5), using: key, counter: counter, nonce: Insecure.ChaCha20CTR.Nonce())
        let ciphertext4 = try Insecure.ChaCha20CTR.encrypt(Array<UInt8>(repeating: 0, count: 5), using: key, counter: counter, nonce: Insecure.ChaCha20CTR.Nonce())
        XCTAssertNotEqual(ciphertext3, ciphertext4)
    }
}
