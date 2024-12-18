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

@testable import _CryptoExtras

final class SLHDSATests: XCTestCase {
    func testSLHDSA_SHA2_128sSigning() throws {
        let key = SLHDSA.SHA2_128s.PrivateKey()
        let test = Data("Hello, World!".utf8)
        let signature = try key.signature(for: test)
        let context = Data("ctx".utf8)

        XCTAssertTrue(
            key.publicKey.isValidSignature(
                signature,
                for: test
            )
        )

        XCTAssertFalse(
            key.publicKey.isValidSignature(
                signature,
                for: test,
                context: context
            )
        )

        try XCTAssertTrue(
            key.publicKey.isValidSignature(
                key.signature(for: test, context: context),
                for: test,
                context: context
            )
        )
    }

    func testSignatureSerialization() throws {
        let data = Array("Hello, World!".utf8)
        let key = SLHDSA.SHA2_128s.PrivateKey()
        let signature = try key.signature(for: data)
        let roundTripped = SLHDSA.SHA2_128s.Signature(rawRepresentation: signature.rawRepresentation)
        XCTAssertEqual(signature.rawRepresentation, roundTripped.rawRepresentation)
        XCTAssertTrue(key.publicKey.isValidSignature(roundTripped, for: data))
    }

    func _testBitFlips() throws {
        let message = "Hello, world!".data(using: .utf8)!
        let key = SLHDSA.SHA2_128s.PrivateKey()
        let publicKey = key.publicKey
        let signature = try key.signature(for: message)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))

        var encodedSignature = signature.rawRepresentation
        for i in 0..<encodedSignature.count {
            for j in 0..<8 {
                encodedSignature[i] ^= 1 << j
                let modifiedSignature = SLHDSA.SHA2_128s.Signature(rawRepresentation: encodedSignature)
                XCTAssertFalse(
                    publicKey.isValidSignature(modifiedSignature, for: message),
                    "Bit flip in signature at byte \(i) bit \(j) didn't cause a verification failure"
                )
                encodedSignature[i] ^= 1 << j
            }
        }
    }

    func testSignatureIsRandomized() throws {
        let message = "Hello, world!".data(using: .utf8)!

        let key = SLHDSA.SHA2_128s.PrivateKey()
        let publicKey = key.publicKey

        let signature1 = try key.signature(for: message)
        let signature2 = try key.signature(for: message)

        XCTAssertNotEqual(signature1.rawRepresentation, signature2.rawRepresentation)

        // Even though the signatures are different, they both verify.
        XCTAssertTrue(publicKey.isValidSignature(signature1, for: message))
        XCTAssertTrue(publicKey.isValidSignature(signature2, for: message))
    }
}
