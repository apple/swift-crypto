//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import XCTest
import _CryptoExtras

final class MLDSATests: XCTestCase {
    func testMLDSASigning() throws {
        testMLDSASigning(MLDSA.PrivateKey())
        // The seed provided here is 64 bytes long, but the MLDSA implementation only uses the first 32 bytes.
        let seed: [UInt8] = (0..<64).map { _ in UInt8.random(in: 0...255) }
        testMLDSASigning(try MLDSA.PrivateKey(from: seed))
    }

    private func testMLDSASigning(_ key: MLDSA.PrivateKey) {
        let test = "Hello, world!".data(using: .utf8)!
        XCTAssertTrue(
            key.publicKey.isValidSignature(
                key.signature(for: test),
                for: test
            )
        )
    }

    func testSignatureSerialization() {
        let data = Array("Hello, World!".utf8)
        let key: MLDSA.PrivateKey = MLDSA.PrivateKey()
        let signature = key.signature(for: data)
        let roundTripped = MLDSA.Signature(rawRepresentation: signature.rawRepresentation)
        XCTAssertEqual(signature.rawRepresentation, roundTripped.rawRepresentation)
        XCTAssertTrue(key.publicKey.isValidSignature(roundTripped, for: data))
    }
}