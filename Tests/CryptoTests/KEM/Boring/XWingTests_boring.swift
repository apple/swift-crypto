//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import XCTest

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// Skip tests that require @testable imports of CryptoKit.
#else
#if !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@testable import CryptoKit
#else
@testable import Crypto
#endif

extension XWingMLKEM768X25519.PrivateKey {
    static func generateWithRng(rngState: SequenceDrbg) throws -> Self {
        // We're going to generate a "random" seed.
        var seed: [UInt8] = []
        seed.reserveCapacity(32)

        for i in 0..<32 {
            seed.append(rngState.state[i % rngState.state.count])
        }

        return try Self(seedRepresentation: seed, publicKey: nil)
    }
}

extension XWingMLKEM768X25519.PublicKey {
    func encapsulateWithRng(rngState: SequenceDrbg) throws -> KEM.EncapsulationResult {
        // We're going to generate "random" entropy
        var seed: [UInt8] = []
        seed.reserveCapacity(64)

        for i in 0..<64 {
            seed.append(rngState.state[i % rngState.state.count])
        }

        return try self.impl.encapsulateWithOptionalEntropy(entropy: seed)
    }
}

extension XWingTests {
    func testIntegrityCheckedRepresentationLengthValidation() throws {
        // Validate that representations with incorrect byte counts fail fast with incorrectParameterSize
        XCTAssertThrowsError(
            try XWingMLKEM768X25519.PrivateKey(integrityCheckedRepresentation: Data()),
            error: CryptoKitError.incorrectParameterSize
        )
        XCTAssertThrowsError(
            try XWingMLKEM768X25519.PrivateKey(integrityCheckedRepresentation: Data(repeating: 0, count: 32)),
            error: CryptoKitError.incorrectParameterSize
        )
        XCTAssertThrowsError(
            try XWingMLKEM768X25519.PrivateKey(integrityCheckedRepresentation: Data(repeating: 0, count: 63)),
            error: CryptoKitError.incorrectParameterSize
        )
        XCTAssertThrowsError(
            try XWingMLKEM768X25519.PrivateKey(integrityCheckedRepresentation: Data(repeating: 0, count: 65)),
            error: CryptoKitError.incorrectParameterSize
        )
        XCTAssertThrowsError(
            try XWingMLKEM768X25519.PrivateKey(integrityCheckedRepresentation: Data(repeating: 0, count: 128)),
            error: CryptoKitError.incorrectParameterSize
        )

        // Validate that seedRepresentation with incorrect byte counts also fails with incorrectParameterSize
        XCTAssertThrowsError(
            try XWingMLKEM768X25519.PrivateKey(seedRepresentation: Data(), publicKey: nil),
            error: CryptoKitError.incorrectParameterSize
        )
        XCTAssertThrowsError(
            try XWingMLKEM768X25519.PrivateKey(seedRepresentation: Data(repeating: 0, count: 31), publicKey: nil),
            error: CryptoKitError.incorrectParameterSize
        )
        XCTAssertThrowsError(
            try XWingMLKEM768X25519.PrivateKey(seedRepresentation: Data(repeating: 0, count: 33), publicKey: nil),
            error: CryptoKitError.incorrectParameterSize
        )
        let dummy = try XWingMLKEM768X25519.PrivateKey()
        XCTAssertThrowsError(
            try XWingMLKEM768X25519.PrivateKey(seedRepresentation: Data(), publicKey: dummy.publicKey),
            error: CryptoKitError.incorrectParameterSize
        )
        XCTAssertThrowsError(
            try XWingMLKEM768X25519.PrivateKey(
                seedRepresentation: Data(repeating: 0, count: 31),
                publicKey: dummy.publicKey
            ),
            error: CryptoKitError.incorrectParameterSize
        )
    }
}

#endif  // CRYPTO_IN_SWIFTPM
