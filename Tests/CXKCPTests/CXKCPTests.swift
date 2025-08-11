//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import XCTest

@testable import CXKCP

final class CXKCPTests: XCTestCase {

    func testSHA3_256() throws {
        // Test data: "abc"
        let input = "abc".data(using: .utf8)!
        var output = [UInt8](repeating: 0, count: 32)

        let result = input.withUnsafeBytes { inputBytes in
            SHA3_256(&output, inputBytes.bindMemory(to: UInt8.self).baseAddress, inputBytes.count)
        }

        // Should return 0 on success
        XCTAssertEqual(result, 0, "SHA3_256 should return 0 on success")

        // Expected SHA3-256 hash of "abc"
        let expectedHex = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        let actualHex = output.map { String(format: "%02x", $0) }.joined()

        XCTAssertEqual(actualHex, expectedHex, "SHA3-256 hash should match expected value")
    }

    func testSHA3_224() throws {
        // Test data: "abc"
        let input = "abc".data(using: .utf8)!
        var output = [UInt8](repeating: 0, count: 28)

        let result = input.withUnsafeBytes { inputBytes in
            SHA3_224(&output, inputBytes.bindMemory(to: UInt8.self).baseAddress, inputBytes.count)
        }

        // Should return 0 on success
        XCTAssertEqual(result, 0, "SHA3_224 should return 0 on success")

        // Expected SHA3-224 hash of "abc"
        let expectedHex = "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
        let actualHex = output.map { String(format: "%02x", $0) }.joined()

        XCTAssertEqual(actualHex, expectedHex, "SHA3-224 hash should match expected value")
    }

    func testSHA3_384() throws {
        // Test data: "abc"
        let input = "abc".data(using: .utf8)!
        var output = [UInt8](repeating: 0, count: 48)

        let result = input.withUnsafeBytes { inputBytes in
            SHA3_384(&output, inputBytes.bindMemory(to: UInt8.self).baseAddress, inputBytes.count)
        }

        // Should return 0 on success
        XCTAssertEqual(result, 0, "SHA3_384 should return 0 on success")

        // Expected SHA3-384 hash of "abc"
        let expectedHex =
            "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
        let actualHex = output.map { String(format: "%02x", $0) }.joined()

        XCTAssertEqual(actualHex, expectedHex, "SHA3-384 hash should match expected value")
    }

    func testSHA3_512() throws {
        // Test data: "abc"
        let input = "abc".data(using: .utf8)!
        var output = [UInt8](repeating: 0, count: 64)

        let result = input.withUnsafeBytes { inputBytes in
            SHA3_512(&output, inputBytes.bindMemory(to: UInt8.self).baseAddress, inputBytes.count)
        }

        // Should return 0 on success
        XCTAssertEqual(result, 0, "SHA3_512 should return 0 on success")

        // Expected SHA3-512 hash of "abc"
        let expectedHex =
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        let actualHex = output.map { String(format: "%02x", $0) }.joined()

        XCTAssertEqual(actualHex, expectedHex, "SHA3-512 hash should match expected value")
    }

    func testSHAKE128() throws {
        // Test data: "abc"
        let input = "abc".data(using: .utf8)!
        var output = [UInt8](repeating: 0, count: 32)  // 256 bits output

        let result = input.withUnsafeBytes { inputBytes in
            SHAKE128(&output, output.count, inputBytes.bindMemory(to: UInt8.self).baseAddress, inputBytes.count)
        }

        // Should return 0 on success
        XCTAssertEqual(result, 0, "SHAKE128 should return 0 on success")

        // Expected SHAKE128 output (first 32 bytes) for "abc"
        let expectedHex = "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
        let actualHex = output.map { String(format: "%02x", $0) }.joined()

        XCTAssertEqual(actualHex, expectedHex, "SHAKE128 output should match expected value")
    }

    func testSHAKE256() throws {
        // Test data: "abc"
        let input = "abc".data(using: .utf8)!
        var output = [UInt8](repeating: 0, count: 32)  // 256 bits output

        let result = input.withUnsafeBytes { inputBytes in
            SHAKE256(&output, output.count, inputBytes.bindMemory(to: UInt8.self).baseAddress, inputBytes.count)
        }

        // Should return 0 on success
        XCTAssertEqual(result, 0, "SHAKE256 should return 0 on success")

        // Expected SHAKE256 output (first 32 bytes) for "abc"
        let expectedHex = "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
        let actualHex = output.map { String(format: "%02x", $0) }.joined()

        XCTAssertEqual(actualHex, expectedHex, "SHAKE256 output should match expected value")
    }
}
