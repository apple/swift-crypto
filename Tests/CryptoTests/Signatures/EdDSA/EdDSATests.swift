//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import XCTest

#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
import Crypto
#elseif (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
import CryptoKit
#else
import Crypto
#endif

class EdDSATests: XCTestCase {
    func testExample() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey

        let someData = "Some Data".data(using: .utf8)!

        let signature = try orFail { try privateKey.signature(for: someData) }

        XCTAssert(publicKey.isValidSignature(signature, for: someData))
    }

    func testSigningDiscontiguousData() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let (someContiguousData, someDiscontiguousData) = Array("Some Data".utf8).asDataProtocols()

        let signatureOnContiguous = try orFail { try privateKey.signature(for: someContiguousData) }
        let signatureOnDiscontiguous = try orFail { try privateKey.signature(for: someDiscontiguousData) }
        #if !(os(macOS) || os(iOS) || os(watchOS) || os(tvOS))
        XCTAssertEqual(signatureOnContiguous, signatureOnDiscontiguous)
        #endif

        // This tests the 4 combinations.
        let (contiguousSignature, discontiguousSignature) = Array(signatureOnContiguous).asDataProtocols()
        XCTAssertTrue(privateKey.publicKey.isValidSignature(contiguousSignature, for: someContiguousData))
        XCTAssertTrue(privateKey.publicKey.isValidSignature(discontiguousSignature, for: someContiguousData))
        XCTAssertTrue(privateKey.publicKey.isValidSignature(contiguousSignature, for: someDiscontiguousData))
        XCTAssertTrue(privateKey.publicKey.isValidSignature(discontiguousSignature, for: someDiscontiguousData))
    }

    func testRejectingInvalidSignaturesOnDiscontiguousData() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let otherPrivateKey = Curve25519.Signing.PrivateKey()
        let (someContiguousData, someDiscontiguousData) = Array("Some Data".utf8).asDataProtocols()

        let signature = try orFail { try privateKey.signature(for: someContiguousData) }

        // This tests the 4 combinations.
        let (contiguousSignature, discontiguousSignature) = Array(signature).asDataProtocols()
        XCTAssertFalse(otherPrivateKey.publicKey.isValidSignature(contiguousSignature, for: someContiguousData))
        XCTAssertFalse(otherPrivateKey.publicKey.isValidSignature(discontiguousSignature, for: someContiguousData))
        XCTAssertFalse(otherPrivateKey.publicKey.isValidSignature(contiguousSignature, for: someDiscontiguousData))
        XCTAssertFalse(otherPrivateKey.publicKey.isValidSignature(discontiguousSignature, for: someDiscontiguousData))
    }

    func testSigningZeroRegionDataProtocol() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let signature = try orFail { try privateKey.signature(for: DispatchData.empty) }

        XCTAssert(privateKey.publicKey.isValidSignature(signature, for: DispatchData.empty))

        // This signature should be invalid
        XCTAssertFalse(privateKey.publicKey.isValidSignature(DispatchData.empty, for: DispatchData.empty))
    }
	
	func testCurve25519SigningPublicKeyEquatable() throws {
		// Equality
		let publicKey = Curve25519.Signing.PrivateKey().publicKey
		XCTAssertEqual(publicKey, publicKey)
		
		// Inequality
		
		// The probability of this inequality check loop
		// accidentally failing is... 1/2^246, i.e. low.
		for _ in 0..<1024 {
			XCTAssertNotEqual(
				publicKey,
				Curve25519.Signing.PrivateKey().publicKey
			)
		}
	}
	
	func testCurve25519KeyAgreementPublicKeyEquatable() throws {
		// Equality
		let publicKey = Curve25519.KeyAgreement.PrivateKey().publicKey
		XCTAssertEqual(publicKey, publicKey)
		
		// Inequality
		
		// The probability of this inequality check loop
		// accidentally failing is... 1/2^246, i.e. low.
		for _ in 0..<1024 {
			XCTAssertNotEqual(
				publicKey,
				Curve25519.KeyAgreement.PrivateKey().publicKey
			)
		}
	}
	
	func testCurve25519SigningPublicKeyHashable() throws {
		let expectedCount = 1000
		let set = Set((0..<expectedCount).map { _ in
			Curve25519.Signing.PrivateKey().publicKey
		})
		XCTAssertEqual(set.count, expectedCount)
	}
	
	func testCurve25519KeyAgreementPublicKeyHashable() throws {
		let expectedCount = 1000
		let set = Set((0..<expectedCount).map { _ in
			Curve25519.KeyAgreement.PrivateKey().publicKey
		})
		XCTAssertEqual(set.count, expectedCount)
	}
}
