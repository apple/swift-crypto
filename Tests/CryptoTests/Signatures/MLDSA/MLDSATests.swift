//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import XCTest
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// Skip tests that require @testable imports of CryptoKit.
#else
#if !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@testable import CryptoKit
#else
@testable import Crypto
#endif

final class MLDSATests: XCTestCase {
    func testMLDSA65() throws {
        let privateKey = try MLDSA65.PrivateKey()
        let publicKey = privateKey.publicKey

        // Test Public Key Serialization
        try XCTAssert(publicKey.rawRepresentation == MLDSA65.PublicKey(rawRepresentation: publicKey.rawRepresentation).rawRepresentation)

        // Test Private Key serialization
        try XCTAssert(privateKey.seedRepresentation == MLDSA65.PrivateKey(seedRepresentation: privateKey.seedRepresentation, publicKey: publicKey).seedRepresentation)
        try XCTAssert(privateKey.integrityCheckedRepresentation == MLDSA65.PrivateKey(integrityCheckedRepresentation: privateKey.integrityCheckedRepresentation).integrityCheckedRepresentation)

        // Test signing without a context
        let message = Data("ML-DSA test message".utf8)
        let signature = try privateKey.signature(for: message)
        XCTAssertNotNil(signature)
        let isValid = publicKey.isValidSignature(signature, for: message)
        XCTAssertTrue(isValid)

        // Test signing with a context
        let context = Data("ML-DSA test context".utf8)
        let signatureWithContext = try privateKey.signature(for: message, context: context)
        let isValidWithContext = publicKey.isValidSignature(signatureWithContext, for: message, context: context)
        XCTAssertTrue(isValidWithContext)

        // Check that invalid signatures (mismatching contexts) fail
        XCTAssertFalse(publicKey.isValidSignature(signature, for: message, context: context))
        XCTAssertFalse(publicKey.isValidSignature(signatureWithContext, for: message))
    }

    func testMLDSA87() throws {
        let privateKey = try MLDSA87.PrivateKey()
        let publicKey = privateKey.publicKey

        // Test Public Key Serialization
        try XCTAssert(publicKey.rawRepresentation == MLDSA87.PublicKey(rawRepresentation: publicKey.rawRepresentation).rawRepresentation)

        // Test Private Key serialization
        try XCTAssert(privateKey.seedRepresentation == MLDSA87.PrivateKey(seedRepresentation: privateKey.seedRepresentation, publicKey: publicKey).seedRepresentation)
        try XCTAssert(privateKey.integrityCheckedRepresentation == MLDSA87.PrivateKey(integrityCheckedRepresentation: privateKey.integrityCheckedRepresentation).integrityCheckedRepresentation)

        // Test signing without a context
        let message = Data("ML-DSA test message".utf8)
        let signature = try privateKey.signature(for: message)
        XCTAssertNotNil(signature)
        let isValid = publicKey.isValidSignature(signature, for: message)
        XCTAssertTrue(isValid)

        // Test signing with a context
        let context = Data("ML-DSA test context".utf8)
        let signatureWithContext = try privateKey.signature(for: message, context: context)
        let isValidWithContext = publicKey.isValidSignature(signatureWithContext, for: message, context: context)
        XCTAssertTrue(isValidWithContext)

        // Check that invalid signatures (mismatching contexts) fail
        XCTAssertFalse(publicKey.isValidSignature(signature, for: message, context: context))
        XCTAssertFalse(publicKey.isValidSignature(signatureWithContext, for: message))
    }
}

#endif // CRYPTO_IN_SWIFTPM
