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

final class SLHDSATests: XCTestCase {
    func testSLHDSASigning() throws {
        let key = SLHDSA.PrivateKey()
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
        let key = SLHDSA.PrivateKey()
        let signature = try key.signature(for: data)
        let roundTripped = SLHDSA.Signature(rawRepresentation: signature.rawRepresentation)
        XCTAssertEqual(signature.rawRepresentation, roundTripped.rawRepresentation)
        XCTAssertTrue(key.publicKey.isValidSignature(roundTripped, for: data))
    }

    func testBitFlips() throws {
        throw XCTSkip("This test is very slow, so it is disabled by default.")

        let message = "Hello, world!".data(using: .utf8)!
        let key = SLHDSA.PrivateKey()
        let publicKey = key.publicKey
        let signature = try key.signature(for: message)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))

        var encodedSignature = signature.rawRepresentation
        for i in 0..<encodedSignature.count {
            for j in 0..<8 {
                encodedSignature[i] ^= 1 << j
                let modifiedSignature = SLHDSA.Signature(rawRepresentation: encodedSignature)
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

        let key = SLHDSA.PrivateKey()
        let publicKey = key.publicKey

        let signature1 = try key.signature(for: message)
        let signature2 = try key.signature(for: message)

        XCTAssertNotEqual(signature1.rawRepresentation, signature2.rawRepresentation)

        // Even though the signatures are different, they both verify.
        XCTAssertTrue(publicKey.isValidSignature(signature1, for: message))
        XCTAssertTrue(publicKey.isValidSignature(signature2, for: message))
    }

    func testPublicKeyASN1Encoding() throws {
        let publicKey = SLHDSA.PrivateKey().publicKey
        let encodedPublicKey = try publicKey.derRepresentation
        let roundTrippedPublicKey = try SLHDSA.PublicKey(derRepresentation: encodedPublicKey)
        try XCTAssertEqual(publicKey.pemRepresentation, roundTrippedPublicKey.pemRepresentation)

        let examplePEMPublicKey = """
            -----BEGIN PUBLIC KEY-----
            MDAwCwYJYIZIAWUDBAMUAyEAK4EJ7Hd8qk4fAkzPz5SX2ZGAUJKA9CVq8rB6+AKJ
            tJQ=
            -----END PUBLIC KEY-----
            """

        let pemPublicKey = try SLHDSA.PublicKey(pemRepresentation: examplePEMPublicKey)
        let pemEncodedPublicKey = try pemPublicKey.derRepresentation
        let pemRoundTrippedPublicKey = try SLHDSA.PublicKey(derRepresentation: pemEncodedPublicKey)
        try XCTAssertEqual(pemPublicKey.pemRepresentation, pemRoundTrippedPublicKey.pemRepresentation)
        try XCTAssertEqual(pemPublicKey.pemRepresentation, examplePEMPublicKey)
    }

    func testPrivateKeyASN1Encoding() throws {
        let privateKey = SLHDSA.PrivateKey()
        let encodedPrivateKey = try privateKey.derRepresentation
        let roundTrippedPrivateKey = try SLHDSA.PrivateKey(derRepresentation: encodedPrivateKey)
        try XCTAssertEqual(privateKey.pemRepresentation, roundTrippedPrivateKey.pemRepresentation)

        let examplePEMPrivateKey = """
            -----BEGIN PRIVATE KEY-----
            MFICAQAwCwYJYIZIAWUDBAMUBECiJjvKRYYINlIxYASVI9YhZ3+tkNUetgZ6Mn4N
            HmSlASuBCex3fKpOHwJMz8+Ul9mRgFCSgPQlavKwevgCibSU
            -----END PRIVATE KEY-----
            """
        
        let pemPrivateKey = try SLHDSA.PrivateKey(pemRepresentation: examplePEMPrivateKey)
        let pemEncodedPrivateKey = try pemPrivateKey.derRepresentation
        let pemRoundTrippedPrivateKey = try SLHDSA.PrivateKey(derRepresentation: pemEncodedPrivateKey)
        try XCTAssertEqual(pemPrivateKey.pemRepresentation, pemRoundTrippedPrivateKey.pemRepresentation)
        try XCTAssertEqual(pemPrivateKey.pemRepresentation, examplePEMPrivateKey)
    }
}
