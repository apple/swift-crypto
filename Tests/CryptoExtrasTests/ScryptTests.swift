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
import XCTest
import Crypto
@testable import CryptoExtras

// Test Vectors are coming from https://tools.ietf.org/html/rfc7914
class ScryptTests: XCTestCase {
    struct RFCTestVector: Codable {
        var inputSecret: [UInt8]
        var salt: [UInt8]
        var rounds: Int
        var blockSize: Int
        var parallelism: Int
        var outputLength: Int
        var derivedKey: [UInt8]

        enum CodingKeys: String, CodingKey {
            case inputSecret = "P"
            case salt = "S"
            case rounds = "N"
            case blockSize = "r"
            case parallelism = "p"
            case outputLength = "dkLen"
            case derivedKey = "DK"
        }
    }

    func oneshotTesting(_ vector: RFCTestVector) throws {
        let (contiguousInput, discontiguousInput) = vector.inputSecret.asDataProtocols()
        let (contiguousSalt, discontiguousSalt) = vector.salt.asDataProtocols()

        let DK1 = try KDF.Scrypt.deriveKey(from: contiguousInput, salt: contiguousSalt,
                                           outputByteCount: vector.outputLength,
                                           rounds: vector.rounds,
                                           blockSize: vector.blockSize,
                                           parallelism: vector.parallelism)

        let DK2 = try KDF.Scrypt.deriveKey(from: discontiguousInput, salt: contiguousSalt,
                                           outputByteCount: vector.outputLength,
                                           rounds: vector.rounds,
                                           blockSize: vector.blockSize,
                                           parallelism: vector.parallelism)

        let DK3 = try KDF.Scrypt.deriveKey(from: contiguousInput, salt: discontiguousSalt,
                                           outputByteCount: vector.outputLength,
                                           rounds: vector.rounds,
                                           blockSize: vector.blockSize,
                                           parallelism: vector.parallelism)

        let DK4 = try KDF.Scrypt.deriveKey(from: discontiguousInput, salt: discontiguousSalt,
                                           outputByteCount: vector.outputLength,
                                           rounds: vector.rounds,
                                           blockSize: vector.blockSize,
                                           parallelism: vector.parallelism)

        let expectedDK = SymmetricKey(data: vector.derivedKey)
        XCTAssertEqual(DK1, expectedDK)
        XCTAssertEqual(DK2, expectedDK)
        XCTAssertEqual(DK3, expectedDK)
        XCTAssertEqual(DK4, expectedDK)
    }

    func testRFCVector(_ vector: RFCTestVector) throws {
        try oneshotTesting(vector)
    }

    func testRfcTestVectors() throws {
        var decoder = try orFail { try RFCVectorDecoder(bundleType: self, fileName: "rfc-7914-scrypt") }
        let vectors = try orFail { try decoder.decode([RFCTestVector].self) }

        for vector in vectors {
            try orFail { try self.testRFCVector(vector) }
        }
    }

    func testDeriveKeyWithMaxMemoryBelowRequirementThrows() throws {
        let password = Array("password".utf8)
        let salt = Array("salt".utf8)

        // These parameters need 128 * blockSize * (rounds + parallelism + 1) bytes, just over 1 MiB.
        // BoringSSL reads a limit of zero as "use the default limit", and a negative limit as a huge size_t.
        for maxMemory in [1024, 0, -1] {
            XCTAssertThrowsError(
                try KDF.Scrypt.deriveKey(
                    from: password,
                    salt: salt,
                    outputByteCount: 32,
                    rounds: 1024,
                    blockSize: 8,
                    parallelism: 1,
                    maxMemory: maxMemory
                )
            )
        }

        let bounded = try KDF.Scrypt.deriveKey(
            from: password,
            salt: salt,
            outputByteCount: 32,
            rounds: 1024,
            blockSize: 8,
            parallelism: 1,
            maxMemory: 2 << 20
        )
        let unbounded = try KDF.Scrypt.deriveKey(
            from: password,
            salt: salt,
            outputByteCount: 32,
            rounds: 1024,
            blockSize: 8,
            parallelism: 1
        )
        XCTAssertEqual(bounded, unbounded)
    }

    func testDeriveKeyWithDefaultMaxMemoryAndBlockSizeAboveRoundsSucceeds() throws {
        // Needs 128 * 1024 * (2 + 1 + 1) bytes, more than 128 * blockSize * rounds * parallelism.
        XCTAssertNoThrow(
            try KDF.Scrypt.deriveKey(
                from: [UInt8](),
                salt: [UInt8](),
                outputByteCount: 32,
                rounds: 2,
                blockSize: 1024,
                parallelism: 1
            )
        )
    }

    func testDeriveKeyWithOutOfRangeParametersThrows() throws {
        let password = Array("password".utf8)
        let salt = Array("salt".utf8)

        for (rounds, blockSize, parallelism, outputByteCount) in [
            // Negative values reach UInt64 conversions and Data(count:), both of which trap.
            (-1, 8, 1, 32),
            (1024, -1, 1, 32),
            (1024, 8, -1, 32),
            (1024, 8, 1, -1),
            // 128 * blockSize * (rounds + parallelism + 1) overflows Int.
            (1 << 32, 1 << 30, 1, 32),
            (1024, 8, .max, 32),
        ] {
            XCTAssertThrowsError(
                try KDF.Scrypt.deriveKey(
                    from: password,
                    salt: salt,
                    outputByteCount: outputByteCount,
                    rounds: rounds,
                    blockSize: blockSize,
                    parallelism: parallelism
                )
            )
        }
    }
}
