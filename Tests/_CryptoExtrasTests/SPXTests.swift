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
        let privateKey = _SPX.PrivateKey()
        let publicKey = _SPX.PublicKey(privateKey: privateKey)
        let message = "Hello, World!".utf8.map { UInt8($0) }
        let signature = privateKey.signature(for: message)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
    }

    func testSPXWithSeed() {
        // The seed provided here is 64 bytes long, but the SPX implementation only uses the first 48 bytes.
        let seed: [UInt8] = (0..<64).map { _ in UInt8.random(in: 0...255) }
        let privateKey = _SPX.PrivateKey(from: seed)
        let publicKey = _SPX.PublicKey(privateKey: privateKey)
        let message = "Hello, World!".utf8.map { UInt8($0) }
        let signature = privateKey.signature(for: message)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
    }

    func testSPXWithRandomizedSignature() {
        let privateKey = _SPX.PrivateKey()
        let publicKey = _SPX.PublicKey(privateKey: privateKey)
        let message = "Hello, World!".utf8.map { UInt8($0) }
        let signature = privateKey.signature(for: message, randomized: true)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
    }

    func testSPXWithSeedAndRandomizedSignature() {
        // The seed provided here is 64 bytes long, but the SPX implementation only uses the first 48 bytes.
        let seed: [UInt8] = (0..<64).map { _ in UInt8.random(in: 0...255) }
        let privateKey = _SPX.PrivateKey(from: seed)
        let publicKey = _SPX.PublicKey(privateKey: privateKey)
        let message = "Hello, World!".utf8.map { UInt8($0) }
        let signature = privateKey.signature(for: message, randomized: true)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
    }
}
