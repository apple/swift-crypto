//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2021-2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import XCTest
import Crypto
@testable import CryptoExtras

// Test Vectors are coming from https://tools.ietf.org/html/rfc6070
class PBKDF2Tests: XCTestCase {
    struct RFCTestVector: Codable {
        var hash: String
        var inputSecret: [UInt8]
        var salt: [UInt8]
        var rounds: Int
        var outputLength: Int
        var derivedKey: [UInt8]

        enum CodingKeys: String, CodingKey {
            case hash = "Hash"
            case inputSecret = "P"
            case salt = "S"
            case rounds = "c"
            case outputLength = "dkLen"
            case derivedKey = "DK"
        }
    }

    func oneshotTesting(_ vector: RFCTestVector, hash: KDF.Insecure.PBKDF2.HashFunction) throws {
        let (contiguousInput, discontiguousInput) = vector.inputSecret.asDataProtocols()
        let (contiguousSalt, discontiguousSalt) = vector.salt.asDataProtocols()

        let DK1 = try KDF.Insecure.PBKDF2.deriveKey(from: contiguousInput, salt: contiguousSalt, using: hash,
                                                    outputByteCount: vector.outputLength,
                                                    unsafeUncheckedRounds: vector.rounds)

        let DK2 = try KDF.Insecure.PBKDF2.deriveKey(from: discontiguousInput, salt: contiguousSalt, using: hash,
                                                    outputByteCount: vector.outputLength,
                                                    unsafeUncheckedRounds: vector.rounds)

        let DK3 = try KDF.Insecure.PBKDF2.deriveKey(from: contiguousInput, salt: discontiguousSalt, using: hash,
                                                    outputByteCount: vector.outputLength,
                                                    unsafeUncheckedRounds: vector.rounds)

        let DK4 = try KDF.Insecure.PBKDF2.deriveKey(from: discontiguousInput, salt: discontiguousSalt, using: hash,
                                                    outputByteCount: vector.outputLength,
                                                    unsafeUncheckedRounds: vector.rounds)

        let expectedDK = SymmetricKey(data: vector.derivedKey)
        XCTAssertEqual(DK1, expectedDK)
        XCTAssertEqual(DK2, expectedDK)
        XCTAssertEqual(DK3, expectedDK)
        XCTAssertEqual(DK4, expectedDK)
    }

    func testRFCVector(_ vector: RFCTestVector, hash: KDF.Insecure.PBKDF2.HashFunction) throws {
        try oneshotTesting(vector, hash: hash)
    }

    func testRfcTestVectorsSHA1() throws {
        var decoder = try orFail { try RFCVectorDecoder(bundleType: self, fileName: "rfc-6070-PBKDF2-SHA1") }
        let vectors = try orFail { try decoder.decode([RFCTestVector].self) }

        for vector in vectors {
            precondition(vector.hash == "SHA-1")
            try orFail { try self.testRFCVector(vector, hash: .insecureSHA1) }
        }
    }

    func testRoundsParameterCheck() {
        let (contiguousInput, contiguousSalt) = (Data("password".utf8), Data("salt".utf8))

        XCTAssertThrowsError(try KDF.Insecure.PBKDF2.deriveKey(from: contiguousInput, salt: contiguousSalt, using: .insecureSHA1,
                                                               outputByteCount: 20, rounds: 209_999))

        XCTAssertNoThrow(try KDF.Insecure.PBKDF2.deriveKey(from: contiguousInput, salt: contiguousSalt, using: .insecureSHA1,
                                                           outputByteCount: 20, unsafeUncheckedRounds: 209_999))

        XCTAssertNoThrow(try KDF.Insecure.PBKDF2.deriveKey(from: contiguousInput, salt: contiguousSalt, using: .insecureSHA1,
                                                           outputByteCount: 20, rounds: 210_000))
    }
}
