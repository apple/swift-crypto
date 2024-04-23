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
    func testSPX() {
        let privateKey = SPX.PrivateKey()
        let publicKey = SPX.PublicKey(privateKey: privateKey)
        let message = "Hello, World!".utf8.map { UInt8($0) }
        let signature = privateKey.signature(for: message)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
    }

    func testSPXPublicKeyFromPrivateKey() {
        let privateKey = SPX.PrivateKey()
        let publicKey = privateKey.publicKey
        let message = "Hello, World!".utf8.map { UInt8($0) }
        let signature = privateKey.signature(for: message)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
    }

    func testSPXWithSeed() {
        // The seed provided here is 64 bytes long, but the SPX implementation only uses the first 48 bytes.
        let seed: [UInt8] = (0..<64).map { _ in UInt8.random(in: 0...255) }
        let privateKey = SPX.PrivateKey(from: seed)
        let publicKey = SPX.PublicKey(privateKey: privateKey)
        let message = "Hello, World!".utf8.map { UInt8($0) }
        let signature = privateKey.signature(for: message)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
    }
    
    func testSPXWithSeedAndPublicKeyFromPrivateKey() {
        // The seed provided here is 64 bytes long, but the SPX implementation only uses the first 48 bytes.
        let seed: [UInt8] = (0..<64).map { _ in UInt8.random(in: 0...255) }
        let privateKey = SPX.PrivateKey(from: seed)
        let publicKey = privateKey.publicKey
        let message = "Hello, World!".utf8.map { UInt8($0) }
        let signature = privateKey.signature(for: message)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
    }

    func testSPXWithRandomizedSignature() {
        let privateKey = SPX.PrivateKey()
        let publicKey = SPX.PublicKey(privateKey: privateKey)
        let message = "Hello, World!".utf8.map { UInt8($0) }
        let signature = privateKey.signature(for: message, randomized: true)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
    }
    
    func testSPXWithRandomizedSignatureAndPublicKeyFromPrivateKey() {
        let privateKey = SPX.PrivateKey()
        let publicKey = privateKey.publicKey
        let message = "Hello, World!".utf8.map { UInt8($0) }
        let signature = privateKey.signature(for: message, randomized: true)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
    }

    func testSPXWithSeedAndRandomizedSignature() {
        // The seed provided here is 64 bytes long, but the SPX implementation only uses the first 48 bytes.
        let seed: [UInt8] = (0..<64).map { _ in UInt8.random(in: 0...255) }
        let privateKey = SPX.PrivateKey(from: seed)
        let publicKey = SPX.PublicKey(privateKey: privateKey)
        let message = "Hello, World!".utf8.map { UInt8($0) }
        let signature = privateKey.signature(for: message, randomized: true)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
    }
    
    func testSPXWithSeedAndRandomizedSignatureAndPublicKeyFromPrivateKey() {
        // The seed provided here is 64 bytes long, but the SPX implementation only uses the first 48 bytes.
        let seed: [UInt8] = (0..<64).map { _ in UInt8.random(in: 0...255) }
        let privateKey = SPX.PrivateKey(from: seed)
        let publicKey = privateKey.publicKey
        let message = "Hello, World!".utf8.map { UInt8($0) }
        let signature = privateKey.signature(for: message, randomized: true)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
    }
}
