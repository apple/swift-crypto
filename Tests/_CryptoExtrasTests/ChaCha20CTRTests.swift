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
import Foundation
import XCTest
import Crypto
import _CryptoExtras

class ChaCha20CTRTests: XCTestCase {

    /// Test Vector - https://datatracker.ietf.org/doc/html/rfc9001#name-chacha20-poly1305-short-hea
    func testChaCha20CTR_v1() throws {
        let hpKey: [UInt8] = [37, 162, 130, 185, 232, 47, 6, 242, 31, 72, 137, 23, 164, 252, 143, 27, 115, 87, 54, 133, 96, 133, 151, 208, 239, 203, 7, 107, 10, 183, 167, 164]
        /// Sample = 0x5e5cd55c41f69080575d7999c25a5bfb
        let counter: UInt32 = Data([94, 92, 213, 92]).withUnsafeBytes { $0.load(as: UInt32.self) }
        let iv: [UInt8] = [65, 246, 144, 128, 87, 93, 121, 153, 194, 90, 91, 251]

        let mask: [UInt8] = try Insecure.ChaCha20CTR.encrypt(Array<UInt8>(repeating: 0, count: 5), using: SymmetricKey(data: hpKey), counter: UInt32(littleEndian: counter), nonce: iv)

        XCTAssertEqual(mask, [174, 254, 254, 125, 3])
    }

    /// Test Vector - https://www.ietf.org/archive/id/draft-ietf-quic-v2-10.html#name-chacha20-poly1305-short-head
    func testChaCha20CTR_v2() throws {
        let hpKey: [UInt8] = [214, 89, 118, 13, 43, 164, 52, 162, 38, 253, 55, 179, 92, 105, 226, 218, 130, 17, 209, 12, 79, 18, 83, 135, 135, 214, 86, 69, 213, 209, 184, 226]
        /// Sample = 0xe7b6b932bc27d786f4bc2bb20f2162ba
        let counter: UInt32 = Data([231, 182, 185, 50]).withUnsafeBytes { $0.load(as: UInt32.self) }
        let iv: [UInt8] = [188, 39, 215, 134, 244, 188, 43, 178, 15, 33, 98, 186]

        let mask: [UInt8] = try Insecure.ChaCha20CTR.encrypt(Array<UInt8>(repeating: 0, count: 5), using: SymmetricKey(data: hpKey), counter: UInt32(littleEndian: counter), nonce: iv)

        XCTAssertEqual(mask, [151, 88, 14, 50, 191])
    }
}
