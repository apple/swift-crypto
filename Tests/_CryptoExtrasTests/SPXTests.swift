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
    func testSPXSigning() {
        testSPXSigning(SPX.PrivateKey())
        // The seed provided here is 64 bytes long, but the SPX implementation only uses the first 48 bytes.
        let seed: [UInt8] = (0..<64).map { _ in UInt8.random(in: 0...255) }
        testSPXSigning(SPX.PrivateKey(from: seed))
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
    }

    func testSignatureSerialization() {
        let data = Array("Hello, World!".utf8)
        let key = SPX.PrivateKey()
        let signature = key.signature(for: data)
        let roundTripped = SPX.Signature(rawRepresentation: signature.rawRepresentation)
        XCTAssertEqual(signature.rawRepresentation, roundTripped.rawRepresentation)
        XCTAssertTrue(key.publicKey.isValidSignature(roundTripped, for: data))
    }

    let hashedData = SHA256.hash(data: Data("Hello, World!".utf8))
    
    func testSPX() {
        let privateKey = SPX.PrivateKey()
        let publicKey = SPX.PublicKey(privateKey: privateKey)
        let signature = privateKey.signature(for: hashedData)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: hashedData))
    }

    func testSPXWithSeed() {
        // The seed provided here is 64 bytes long, but the SPX implementation only uses the first 48 bytes.
        let seed: [UInt8] = (0..<64).map { _ in UInt8.random(in: 0...255) }
        let privateKey = SPX.PrivateKey(from: seed)
        let publicKey = SPX.PublicKey(privateKey: privateKey)
        let signature = privateKey.signature(for: hashedData)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: hashedData))
    }

    func testSPXWithRandomizedSignature() {
        let privateKey = SPX.PrivateKey()
        let publicKey = SPX.PublicKey(privateKey: privateKey)
        let signature = privateKey.signature(for: hashedData, randomized: true)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: hashedData))
    }
    
    func testSPXWithRandomizedSignatureAndPublicKeyFromPrivateKey() {
        let key = SPX.PrivateKey()
        XCTAssertTrue(
            key.publicKey.isValidSignature(
                key.signature(for: hashedData, randomized: true),
                for: hashedData
            )
        )
    }

    func testSPXWithSeedAndRandomizedSignature() {
        // The seed provided here is 64 bytes long, but the SPX implementation only uses the first 48 bytes.
        let seed: [UInt8] = (0..<64).map { _ in UInt8.random(in: 0...255) }
        let privateKey = SPX.PrivateKey(from: seed)
        let publicKey = SPX.PublicKey(privateKey: privateKey)
        let signature = privateKey.signature(for: hashedData, randomized: true)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: hashedData))
    }
    
    func testSPXWithSeedAndRandomizedSignatureAndPublicKeyFromPrivateKey() {
        // The seed provided here is 64 bytes long, but the SPX implementation only uses the first 48 bytes.
        let seed: [UInt8] = (0..<64).map { _ in UInt8.random(in: 0...255) }
        let key = SPX.PrivateKey(from: seed)
        XCTAssertTrue(
            key.publicKey.isValidSignature(
                key.signature(for: hashedData, randomized: true),
                for: hashedData
            )
        )
    }
}
