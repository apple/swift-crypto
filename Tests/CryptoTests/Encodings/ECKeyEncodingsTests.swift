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
// Skip tests that require @testable imports of CryptoKit.
#else
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@testable import CryptoKit
#else
@testable import Crypto
#endif

class ECKeyEncodingsTests: XCTestCase {
    func testEncodingsKeyAgreement() {
        let p256KeyKA = P256.KeyAgreement.PrivateKey()
        let p256KeyKA_raw = p256KeyKA.rawRepresentation
        let p256KeyKA_x963 = p256KeyKA.x963Representation
        XCTAssertNoThrow(try P256.KeyAgreement.PrivateKey(rawRepresentation: p256KeyKA_raw))
        XCTAssertNoThrow(try P256.KeyAgreement.PrivateKey(x963Representation: p256KeyKA_x963))
        
        let p384KeyKA = P384.KeyAgreement.PrivateKey()
        let p384KeyKA_raw = p384KeyKA.rawRepresentation
        let p384KeyKA_x963 = p384KeyKA.x963Representation
        XCTAssertNoThrow(try P384.KeyAgreement.PrivateKey(rawRepresentation: p384KeyKA_raw))
        XCTAssertNoThrow(try P384.KeyAgreement.PrivateKey(x963Representation: p384KeyKA_x963))
        
        let p521KeyKA = P521.KeyAgreement.PrivateKey()
        let p521KeyKA_raw = p521KeyKA.rawRepresentation
        let p521KeyKA_x963 = p521KeyKA.x963Representation
        XCTAssertNoThrow(try P521.KeyAgreement.PrivateKey(rawRepresentation: p521KeyKA_raw))
        XCTAssertNoThrow(try P521.KeyAgreement.PrivateKey(x963Representation: p521KeyKA_x963))

        // Curve25519 does not have an x963 representation.
        let x25519KeyKA = Curve25519.KeyAgreement.PrivateKey()
        let x25519KeyKA_raw = x25519KeyKA.rawRepresentation
        XCTAssertNoThrow(try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: x25519KeyKA_raw))
    }
    
    func testEncodingsSigningKeyTests() {
        let p256KeyKA = P256.Signing.PrivateKey()
        let p256KeyKA_raw = p256KeyKA.rawRepresentation
        let p256KeyKA_x963 = p256KeyKA.x963Representation
        XCTAssertNoThrow(try P256.Signing.PrivateKey(rawRepresentation: p256KeyKA_raw))
        XCTAssertNoThrow(try P256.Signing.PrivateKey(x963Representation: p256KeyKA_x963))
        
        let p384KeyKA = P384.Signing.PrivateKey()
        let p384KeyKA_raw = p384KeyKA.rawRepresentation
        let p384KeyKA_x963 = p384KeyKA.x963Representation
        XCTAssertNoThrow(try P384.Signing.PrivateKey(rawRepresentation: p384KeyKA_raw))
        XCTAssertNoThrow(try P384.Signing.PrivateKey(x963Representation: p384KeyKA_x963))
        
        let p521KeyKA = P521.Signing.PrivateKey()
        let p521KeyKA_raw = p521KeyKA.rawRepresentation
        let p521KeyKA_x963 = p521KeyKA.x963Representation
        XCTAssertNoThrow(try P521.Signing.PrivateKey(rawRepresentation: p521KeyKA_raw))
        XCTAssertNoThrow(try P521.Signing.PrivateKey(x963Representation: p521KeyKA_x963))

        let x25519KeyKA = Curve25519.Signing.PrivateKey()
        let x25519KeyKA_raw = x25519KeyKA.rawRepresentation
        XCTAssertNoThrow(try Curve25519.Signing.PrivateKey(rawRepresentation: x25519KeyKA_raw))
    }

    func testEncodingsKeyAgreementPublicKeys() {
        let p256KeyKA = P256.KeyAgreement.PrivateKey().publicKey
        let p256KeyKA_raw = p256KeyKA.rawRepresentation
        let p256KeyKA_x963 = p256KeyKA.x963Representation
        XCTAssertNoThrow(try P256.KeyAgreement.PublicKey(rawRepresentation: p256KeyKA_raw))
        XCTAssertNoThrow(try P256.KeyAgreement.PublicKey(x963Representation: p256KeyKA_x963))

        let p384KeyKA = P384.KeyAgreement.PrivateKey().publicKey
        let p384KeyKA_raw = p384KeyKA.rawRepresentation
        let p384KeyKA_x963 = p384KeyKA.x963Representation
        XCTAssertNoThrow(try P384.KeyAgreement.PublicKey(rawRepresentation: p384KeyKA_raw))
        XCTAssertNoThrow(try P384.KeyAgreement.PublicKey(x963Representation: p384KeyKA_x963))

        let p521KeyKA = P521.KeyAgreement.PrivateKey().publicKey
        let p521KeyKA_raw = p521KeyKA.rawRepresentation
        let p521KeyKA_x963 = p521KeyKA.x963Representation
        XCTAssertNoThrow(try P521.KeyAgreement.PublicKey(rawRepresentation: p521KeyKA_raw))
        XCTAssertNoThrow(try P521.KeyAgreement.PublicKey(x963Representation: p521KeyKA_x963))

        // Curve25519 does not have an x963 representation.
        let x25519KeyKA = Curve25519.KeyAgreement.PrivateKey().publicKey
        let x25519KeyKA_raw = x25519KeyKA.rawRepresentation
        XCTAssertNoThrow(try Curve25519.KeyAgreement.PublicKey(rawRepresentation: x25519KeyKA_raw))
    }

    func testEncodingsSigningKeyPublicKeys() {
        let p256KeyKA = P256.Signing.PrivateKey().publicKey
        let p256KeyKA_raw = p256KeyKA.rawRepresentation
        let p256KeyKA_x963 = p256KeyKA.x963Representation
        XCTAssertNoThrow(try P256.Signing.PublicKey(rawRepresentation: p256KeyKA_raw))
        XCTAssertNoThrow(try P256.Signing.PublicKey(x963Representation: p256KeyKA_x963))

        let p384KeyKA = P384.Signing.PrivateKey().publicKey
        let p384KeyKA_raw = p384KeyKA.rawRepresentation
        let p384KeyKA_x963 = p384KeyKA.x963Representation
        XCTAssertNoThrow(try P384.Signing.PublicKey(rawRepresentation: p384KeyKA_raw))
        XCTAssertNoThrow(try P384.Signing.PublicKey(x963Representation: p384KeyKA_x963))

        let p521KeyKA = P521.Signing.PrivateKey().publicKey
        let p521KeyKA_raw = p521KeyKA.rawRepresentation
        let p521KeyKA_x963 = p521KeyKA.x963Representation
        XCTAssertNoThrow(try P521.Signing.PublicKey(rawRepresentation: p521KeyKA_raw))
        XCTAssertNoThrow(try P521.Signing.PublicKey(x963Representation: p521KeyKA_x963))

        let x25519KeyKA = Curve25519.Signing.PrivateKey().publicKey
        let x25519KeyKA_raw = x25519KeyKA.rawRepresentation
        XCTAssertNoThrow(try Curve25519.Signing.PublicKey(rawRepresentation: x25519KeyKA_raw))
    }

    func testEncodingsKeyAgreementCompactRepresentation() {
        let p256KeyKA = P256.KeyAgreement.PrivateKey(compactRepresentable: true).publicKey
        let p256KeyKA_compact = p256KeyKA.compactRepresentation!
        XCTAssertNoThrow(try P256.KeyAgreement.PublicKey(compactRepresentation: p256KeyKA_compact))

        let p384KeyKA = P384.KeyAgreement.PrivateKey(compactRepresentable: true).publicKey
        let p384KeyKA_compact = p384KeyKA.compactRepresentation!
        XCTAssertNoThrow(try P384.KeyAgreement.PublicKey(compactRepresentation: p384KeyKA_compact))

        let p521KeyKA = P521.KeyAgreement.PrivateKey(compactRepresentable: true).publicKey
        let p521KeyKA_compact = p521KeyKA.compactRepresentation!
        XCTAssertNoThrow(try P521.KeyAgreement.PublicKey(compactRepresentation: p521KeyKA_compact))
    }

    func testEncodingsSigningCompactRepresentation() {
        let p256KeyKA = P256.Signing.PrivateKey(compactRepresentable: true).publicKey
        let p256KeyKA_compact = p256KeyKA.compactRepresentation!
        XCTAssertNoThrow(try P256.Signing.PublicKey(compactRepresentation: p256KeyKA_compact))

        let p384KeyKA = P384.Signing.PrivateKey(compactRepresentable: true).publicKey
        let p384KeyKA_compact = p384KeyKA.compactRepresentation!
        XCTAssertNoThrow(try P384.Signing.PublicKey(compactRepresentation: p384KeyKA_compact))

        let p521KeyKA = P521.Signing.PrivateKey(compactRepresentable: true).publicKey
        let p521KeyKA_compact = p521KeyKA.compactRepresentation!
        XCTAssertNoThrow(try P521.Signing.PublicKey(compactRepresentation: p521KeyKA_compact))
    }
}
#endif // (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM
