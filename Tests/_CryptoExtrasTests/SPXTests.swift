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

import Foundation
import XCTest
@testable import Crypto
import _CryptoExtras

final class SPXTests: XCTestCase {
    func testSPXSigning() throws {
        testSPXSigning(SPX.PrivateKey())
        // The seed provided here is 64 bytes long, but the SPX implementation only uses the first 48 bytes.
        let seed: [UInt8] = (0..<64).map { _ in UInt8.random(in: 0...255) }
        testSPXSigning(try SPX.PrivateKey(from: seed))

        try testSPXSigning(SPX.PrivateKey(pemRepresentation: spx128sPrivateKey))
        XCTAssertEqual(
            try SPX.PrivateKey(pemRepresentation: spx128sPrivateKey).publicKey.pemRepresentation,
            spx128sPublicKey
        )
        XCTAssertEqual(
            try SPX.PrivateKey(pemRepresentation: spx128sPrivateKey).signature(for: Data("Hello, World!".utf8)).rawRepresentation.base64EncodedString(),
            spx128sSignature
        )
    }

    private func testSPXSigning(_ key: SPX.PrivateKey) {
        let test = Data("Hello, World!".utf8)

        // Test pre hashed.
        let preHashedSha256 = SHA256.hash(data: test)
        XCTAssertTrue(
            key.publicKey.isValidSignature(
                key.signature(for: preHashedSha256),
                for: preHashedSha256
            )
        )

        // Test pre-hashed with other hash function
        let preHashedSha512 = SHA512.hash(data: test)
        XCTAssertTrue(
            key.publicKey.isValidSignature(
                key.signature(for: preHashedSha512),
                for: preHashedSha512
            )
        )

        // Test unhashed
        XCTAssertTrue(
            key.publicKey.isValidSignature(
                key.signature(for: test),
                for: test
            )
        )

        // Test unhashed corresponds to SHA256
        XCTAssertTrue(
            key.publicKey.isValidSignature(
                key.signature(for: test),
                for: preHashedSha256
            )
        )
        XCTAssertTrue(
            key.publicKey.isValidSignature(
                key.signature(for: preHashedSha256),
                for: test
            )
        )
        
        // Test randomized signature
        XCTAssertTrue(
            key.publicKey.isValidSignature(
                key.signature(for: preHashedSha256, randomized: true),
                for: preHashedSha256
            )
        )
    }

    func testSignatureSerialization() {
        let data = Array("Hello, World!".utf8)
        let key = SPX.PrivateKey()
        let signature = key.signature(for: data)
        let roundTripped = SPX.Signature(rawRepresentation: signature.rawRepresentation)
        XCTAssertEqual(signature.rawRepresentation, roundTripped.rawRepresentation)
        XCTAssertTrue(key.publicKey.isValidSignature(roundTripped, for: data))
    }
    
    let spx128sPrivateKey = """
    -----BEGIN PRIVATE KEY-----
    Jyl8Ef+FbvH9voZx/Y0kM+VNs3SNYw/PqLX47eN5haokJW+Qx/7+5KAevFwGhDGR
    Q8DmXAf+gNKuOxQHmEOcMg==
    -----END PRIVATE KEY-----
    """
    
    let spx128sPublicKey = """
    -----BEGIN PUBLIC KEY-----
    JCVvkMf+/uSgHrxcBoQxkUPA5lwH/oDSrjsUB5hDnDI=
    -----END PUBLIC KEY-----
    """
    
    let spx128sSignature = """
    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
    """
}
