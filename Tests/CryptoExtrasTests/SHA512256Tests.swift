//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import CryptoExtras
import XCTest

final class SHA512256DigestTests: XCTestCase {
    func testHashFunction() throws {
        let data =
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            .data(using: .ascii)!

        var hasher = SHA512256()
        hasher.update(data: data)
        let digest = hasher.finalize()

        let expected = try Array(hexString: "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a")
        XCTAssertEqual(Array(digest), expected)
        XCTAssertEqual(Array(SHA512256.hash(data: data)), expected)

        let (contiguousResult, discontiguousResult) = expected.asDataProtocols()
        XCTAssert(digest == contiguousResult)
        XCTAssert(digest == discontiguousResult)
        XCTAssertFalse(digest == DispatchData.empty)
    }

    func testNullHash() throws {
        let digest = SHA512256.hash(data: Data())

        let expected = try Array(hexString: "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a")
        XCTAssertEqual(Array(digest), expected)
    }

    func testABC() throws {
        let digest = SHA512256.hash(data: "abc".data(using: .ascii)!)

        let expected = try Array(hexString: "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23")
        XCTAssertEqual(Array(digest), expected)
    }

    func testTwoBlockMessage() throws {
        let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopmopq".data(using: .ascii)!
        let digest = SHA512256.hash(data: data)

        let expected = try Array(hexString: "35de8c8794b9ed4b463c257fe50e62b516e07976a2931f4f78f1cd69a456dccd")
        XCTAssertEqual(Array(digest), expected)
    }

    func testSingleByte() throws {
        let digest = SHA512256.hash(data: Data([0x61]))

        let expected = try Array(hexString: "455e518824bc0601f9fb858ff5c37d417d67c2f8e0df2babe4808858aea830f8")
        XCTAssertEqual(Array(digest), expected)
    }

    func testRepeatedBytes() throws {
        let data = Data(repeating: 0x61, count: 1_000_000)
        let digest = SHA512256.hash(data: data)

        let expected = try Array(hexString: "9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21")
        XCTAssertEqual(Array(digest), expected)
    }

    func testCopyOnWrite() {
        var hasher = SHA512256()
        hasher.update(data: [1, 2, 3, 4])

        var copy = hasher
        hasher.update(data: [5, 6, 7, 8])
        let digest = hasher.finalize()

        copy.update(data: [5, 6, 7, 8])
        let copyDigest = copy.finalize()

        XCTAssertEqual(digest, copyDigest)
    }

    func testBlockSize() {
        XCTAssertEqual(SHA512256.blockByteCount, 128)
    }

    func testDigestByteCount() {
        XCTAssertEqual(SHA512256Digest.byteCount, 32)
    }
}
