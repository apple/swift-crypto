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
import CryptoBoringWrapper
@testable import CryptoExtras
import XCTest

final class AES_CFBTests: XCTestCase {
    /// Test vectors from NIST, of the following form:
    /// ```
    /// COUNT = 0
    /// KEY = 00000000000000000000000000000000
    /// IV = f34481ec3cc627bacd5dc3fb08f273e6
    /// PLAINTEXT = 00000000000000000000000000000000
    /// CIPHERTEXT = 0336763e966d92595a567cc9ce537f5e
    /// ```
    /// —— source: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers
    struct TestVector: Codable {
        var count: Int
        var key: [UInt8]
        var iv: [UInt8]
        var plaintext: [UInt8]
        var ciphertext: [UInt8]

        enum CodingKeys: String, CodingKey {
            case count = "COUNT"
            case key = "KEY"
            case iv = "IV"
            case plaintext = "PLAINTEXT"
            case ciphertext = "CIPHERTEXT"
        }
    }

    func testVector(_ vector: TestVector) throws {
        let (contiguousPlaintextData, discontiguousPlaintextData) = vector.plaintext.asDataProtocols()
        for plaintextData in [contiguousPlaintextData as DataProtocol, discontiguousPlaintextData as DataProtocol] {
            let key = SymmetricKey(data: Data(vector.key))
            let iv = try AES._CFB.IV(ivBytes: vector.iv)
            let ciphertext = try AES._CFB.encrypt(plaintextData, using: key, iv: iv)
            XCTAssertEqual(ciphertext, Data(vector.ciphertext))
        }
    }

    func testVectorsFrom(fileName: String) throws {
        var decoder = try RFCVectorDecoder(bundleType: self, fileName: fileName)
        let vectors = try decoder.decode([TestVector].self)
        for vector in vectors {
            try self.testVector(vector)
        }
    }

    func testVectors() throws {
        try self.testVectorsFrom(fileName: "AESCFB128GFSbox128")
        try self.testVectorsFrom(fileName: "AESCFB128GFSbox128")
        try self.testVectorsFrom(fileName: "AESCFB128GFSbox128")
        try self.testVectorsFrom(fileName: "AESCFB128GFSbox192")
        try self.testVectorsFrom(fileName: "AESCFB128GFSbox256")
        try self.testVectorsFrom(fileName: "AESCFB128KeySbox128")
        try self.testVectorsFrom(fileName: "AESCFB128KeySbox192")
        try self.testVectorsFrom(fileName: "AESCFB128KeySbox256")
        try self.testVectorsFrom(fileName: "AESCFB128VarKey128")
        try self.testVectorsFrom(fileName: "AESCFB128VarKey192")
        try self.testVectorsFrom(fileName: "AESCFB128VarKey256")
        try self.testVectorsFrom(fileName: "AESCFB128VarTxt128")
        try self.testVectorsFrom(fileName: "AESCFB128VarTxt192")
        try self.testVectorsFrom(fileName: "AESCFB128VarTxt256")
    }

    func testRoundtrip() throws {
        let key = SymmetricKey(size: .bits128)
        let plaintext = Data(SystemRandomNumberGenerator.randomBytes(count: 1024))
        let iv = AES._CFB.IV()
        let ciphertext = try AES._CFB.encrypt(plaintext, using: key, iv: iv)
        XCTAssertEqual(try AES._CFB.decrypt(ciphertext, using: key, iv: iv), plaintext)
    }

    func testRejectsInvalidIVSizes() throws {
        let someBytes = Array(repeating: UInt8(0), count: 24)

        for count in 0..<someBytes.count {
            let ivBytes = someBytes.prefix(count)

            if count != 16 {
                XCTAssertThrowsError(try AES._CFB.IV(ivBytes: ivBytes))
            } else {
                XCTAssertNoThrow(try AES._CFB.IV(ivBytes: ivBytes))
            }
        }
    }
}
