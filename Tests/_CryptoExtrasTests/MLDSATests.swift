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
@testable import _CryptoExtras

final class MLDSATests: XCTestCase {
    func testMLDSASigning() throws {
        try testMLDSASigning(MLDSA.PrivateKey())
        // The seed provided here is 64 bytes long, but the MLDSA implementation only uses the first 32 bytes.
        let seed: [UInt8] = (0..<64).map { _ in UInt8.random(in: 0...255) }
        try testMLDSASigning(MLDSA.PrivateKey(from: seed))
    }

    private func testMLDSASigning(_ key: MLDSA.PrivateKey) throws {
        let test = "Hello, world!".data(using: .utf8)!
        try XCTAssertTrue(
            key.publicKey.isValidSignature(
                key.signature(for: test),
                for: test
            )
        )
        
        let context: [UInt8] = [UInt8]("ctx".utf8)
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
        let key: MLDSA.PrivateKey = try MLDSA.PrivateKey()
        let signature = try key.signature(for: data)
        let roundTripped = MLDSA.Signature(rawRepresentation: signature.rawRepresentation)
        XCTAssertEqual(signature.rawRepresentation, roundTripped.rawRepresentation)
        try XCTAssertTrue(key.publicKey.isValidSignature(roundTripped, for: data))
    }

    func testBitFlips() throws {
        throw XCTSkip("This test is very slow, so it is disabled by default.")

        let message = "Hello, world!".data(using: .utf8)!
        let key = try MLDSA.PrivateKey()
        let publicKey = try key.publicKey
        let signature = try key.signature(for: message)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
        
        var encodedSignature = signature.rawRepresentation
        for i in 0..<encodedSignature.count {
            for j in 0..<8 {
                encodedSignature[i] ^= 1 << j
                let modifiedSignature = MLDSA.Signature(rawRepresentation: encodedSignature)
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
        
        let seed: [UInt8] = (0..<32).map { _ in UInt8.random(in: 0...255) }
        let key = try MLDSA.PrivateKey(from: seed)
        let publicKey = try key.publicKey
        
        let signature1 = try key.signature(for: message)
        let signature2 = try key.signature(for: message)
        
        XCTAssertNotEqual(signature1.rawRepresentation, signature2.rawRepresentation)
        
        // Even though the signatures are different, they both verify.
        XCTAssertTrue(publicKey.isValidSignature(signature1, for: message))
        XCTAssertTrue(publicKey.isValidSignature(signature2, for: message))
    }

    func testInvalidPublicKeyEncodingLength() throws {
        // Encode a public key with a trailing 0 at the end.
        var encodedPublicKey = [UInt8](repeating: 0, count: MLDSA.PublicKey.bytesCount + 1)
        let seed: [UInt8] = (0..<32).map { _ in UInt8.random(in: 0...255) }
        let key = try MLDSA.PrivateKey(from: seed)
        let publicKey = try key.publicKey
        try encodedPublicKey.replaceSubrange(0..<MLDSA.PublicKey.bytesCount, with: publicKey.derRepresentation)
        
        // Public key is 1 byte too short.
        let shortPublicKey = Array(encodedPublicKey.prefix(MLDSA.PublicKey.bytesCount - 1))
        XCTAssertThrowsError(try MLDSA.PublicKey(derRepresentation: shortPublicKey))
        
        // Public key has the correct length.
        let correctLengthPublicKey = Array(encodedPublicKey.prefix(MLDSA.PublicKey.bytesCount))
        XCTAssertNoThrow(try MLDSA.PublicKey(derRepresentation: correctLengthPublicKey))
        
        // Public key is 1 byte too long.
        XCTAssertThrowsError(try MLDSA.PublicKey(derRepresentation: encodedPublicKey))
    }
}