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

import CryptoExtras
import XCTest

final class Curve25519DERTests: XCTestCase {
    func testSigningPrivateKeyDERRoundTrip() throws {
        let privateKey = Curve25519.Signing.PrivateKey()

        let der = privateKey.derRepresentation
        let imported = try Curve25519.Signing.PrivateKey(derRepresentation: der)

        XCTAssertEqual(imported.rawRepresentation, privateKey.rawRepresentation)
    }

    func testSigningPublicKeyDERRoundTrip() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey

        let der = publicKey.derRepresentation
        let imported = try Curve25519.Signing.PublicKey(derRepresentation: der)

        XCTAssertEqual(imported.rawRepresentation, publicKey.rawRepresentation)
    }

    func testKeyAgreementPrivateKeyDERRoundTrip() throws {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()

        let der = privateKey.derRepresentation
        let imported = try Curve25519.KeyAgreement.PrivateKey(derRepresentation: der)

        XCTAssertEqual(imported.rawRepresentation, privateKey.rawRepresentation)
    }

    func testKeyAgreementPublicKeyDERRoundTrip() throws {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey

        let der = publicKey.derRepresentation
        let imported = try Curve25519.KeyAgreement.PublicKey(derRepresentation: der)

        XCTAssertEqual(imported.rawRepresentation, publicKey.rawRepresentation)
    }

    func testInvalidDERThrows() throws {
        let invalidDER: [UInt8] = [0x01, 0x02, 0x03]

        XCTAssertThrowsError(try Curve25519.Signing.PrivateKey(derRepresentation: invalidDER))
        XCTAssertThrowsError(try Curve25519.Signing.PublicKey(derRepresentation: invalidDER))
        XCTAssertThrowsError(try Curve25519.KeyAgreement.PrivateKey(derRepresentation: invalidDER))
        XCTAssertThrowsError(try Curve25519.KeyAgreement.PublicKey(derRepresentation: invalidDER))
    }

    func testImportOpenSSLSigningPrivateKeyDER() throws {
        // DER extracted from an OpenSSL-generated Ed25519 PKCS#8 PEM
        let derBytes: [UInt8] = [
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
            0x04, 0x22, 0x04, 0x20, 0x3f, 0x10, 0x52, 0x03, 0xb4, 0x06, 0x87, 0x0c,
            0x51, 0x71, 0xfa, 0xdc, 0x8f, 0x96, 0xbd, 0x2a, 0x5f, 0x42, 0xac, 0x5c,
            0xb9, 0x5b, 0x27, 0x4e, 0xf0, 0x06, 0xe5, 0x61, 0x6a, 0x12, 0x00, 0xa5,
        ]

        let key = try Curve25519.Signing.PrivateKey(derRepresentation: derBytes)
        XCTAssertEqual(key.rawRepresentation.count, 32)
    }

    func testImportOpenSSLKeyAgreementPrivateKeyDER() throws {
        // DER extracted from an OpenSSL-generated X25519 PKCS#8 PEM
        let derBytes: [UInt8] = [
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
            0x04, 0x22, 0x04, 0x20, 0xb8, 0x38, 0x3f, 0x28, 0xea, 0x8f, 0x1d, 0x71,
            0x49, 0xa2, 0xa3, 0x91, 0x37, 0x00, 0xa1, 0x0c, 0x7c, 0x9d, 0xa9, 0x59,
            0x28, 0x2d, 0x14, 0x7e, 0x9b, 0x1e, 0x1b, 0x8c, 0x04, 0xa5, 0xd8, 0x47,
        ]

        let key = try Curve25519.KeyAgreement.PrivateKey(derRepresentation: derBytes)
        XCTAssertEqual(key.rawRepresentation.count, 32)
    }
}
