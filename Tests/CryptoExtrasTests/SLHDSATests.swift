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
        let message = Data("Hello, World!".utf8)
        let signature = try key.signature(for: message)

        XCTAssertTrue(
            key.publicKey.isValidSignature(
                signature,
                for: message
            )
        )

        let context = Data("ctx".utf8)

        XCTAssertFalse(
            key.publicKey.isValidSignature(
                signature,
                for: message,
                context: context
            )
        )

        try XCTAssertTrue(
            key.publicKey.isValidSignature(
                key.signature(for: message, context: context),
                for: message,
                context: context
            )
        )
    }

    func testEmptyMessageAndContext() throws {
        let key = SLHDSA.SHA2_128s.PrivateKey()
        let emptyMessage = Data("".utf8)
        let emptyContext = Data("".utf8)

        try XCTAssertTrue(
            key.publicKey.isValidSignature(
                key.signature(for: emptyMessage, context: emptyContext),
                for: emptyMessage,
                context: emptyContext
            )
        )
    }

    func testMaxContextLenght() throws {
        let key = SLHDSA.SHA2_128s.PrivateKey()
        let message = Array("Hello, World!".utf8)

        let context = [UInt8](repeating: 0, count: 255)  // Maximum allowed context length
        try XCTAssertTrue(
            key.publicKey.isValidSignature(
                key.signature(for: message, context: context),
                for: message,
                context: context
            )
        )

        let tooLongContext = [UInt8](repeating: 0, count: 256)
        XCTAssertThrowsError(
            try key.signature(for: message, context: tooLongContext)
        )
    }

    func testSignatureIsRandomized() throws {
        let message = "Hello, world!".data(using: .utf8)!

        let key = SLHDSA.SHA2_128s.PrivateKey()
        let publicKey = key.publicKey

        let signature1 = try key.signature(for: message)
        let signature2 = try key.signature(for: message)

        XCTAssertNotEqual(signature1, signature2)

        // Even though the signatures are different, they both verify.
        XCTAssertTrue(publicKey.isValidSignature(signature1, for: message))
        XCTAssertTrue(publicKey.isValidSignature(signature2, for: message))
    }
}
