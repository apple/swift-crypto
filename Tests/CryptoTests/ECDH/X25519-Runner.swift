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
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import XCTest

#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// Skip tests that require @testable imports of CryptoKit.
#else
#if !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@testable import CryptoKit
#else
@testable import Crypto
#endif

struct ECDHTestGroup: Codable {
    let curve: String
    let tests: [ECDHTestVector]
}

struct ECDHTestVector: Codable {
    let comment: String
    let publicKey: String
    let privateKey: String
    let shared: String
    let result: String
    let tcId: Int
    let flags: [String]

    enum CodingKeys: String, CodingKey {
        case publicKey = "public"
        case privateKey = "private"
        case comment
        case shared
        case result
        case tcId
        case flags
    }
}

class X25519Tests: XCTestCase {
    func testSerialization() throws {
        let bobsKey = Curve25519.KeyAgreement.PrivateKey()
        
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let keyData = privateKey.rawRepresentation
        
        let recoveredKey = try orFail { try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: keyData) }
        
        let ss1 = try orFail { try privateKey.sharedSecretFromKeyAgreement(with: bobsKey.publicKey) }
        let ss2 = try orFail { try recoveredKey.sharedSecretFromKeyAgreement(with: bobsKey.publicKey) }
        
        XCTAssertEqual(ss1, ss2)
        XCTAssertEqual(recoveredKey.rawRepresentation, keyData)
    }

    func testCompressedKeys() throws {
        let x963Positive = Data(base64Encoded: "A+QHCXtGd5WWSQgp37FBPXMy+nnSwFK79QQD0ZeNMv7L")!
        let key = try P256.KeyAgreement.PublicKey(compressedRepresentation: x963Positive)
        XCTAssertEqual(
            key.x963Representation.base64EncodedString(),
            "BOQHCXtGd5WWSQgp37FBPXMy+nnSwFK79QQD0ZeNMv7LE6xvfFkB4Y3VXoOpB/Kp6ngpf3Lce9hDMl7fqaDUfYE="
        )

        let x963Negative = Data(base64Encoded: "AuQHCXtGd5WWSQgp37FBPXMy+nnSwFK79QQD0ZeNMv7L")!
        let negativeKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: x963Negative)
        XCTAssertEqual(
            negativeKey.x963Representation.base64EncodedString(),
            "BOQHCXtGd5WWSQgp37FBPXMy+nnSwFK79QQD0ZeNMv7L7FOQgqb+HnMqoXxW+A1WFYfWgI4jhCe8zaEgVl8rgn4="
        )

        let p384Positive = Data(base64Encoded: "AyEfGE5ySReJyfSruLRdsjvCB5RNWGLk8JYrzIrans3MprXf5Q4nh69bQ2rI4+DNpw==")!
        let p384Key = try P384.KeyAgreement.PublicKey(compressedRepresentation: p384Positive)
        XCTAssertEqual(
            p384Key.x963Representation.base64EncodedString(),
            "BCEfGE5ySReJyfSruLRdsjvCB5RNWGLk8JYrzIrans3MprXf5Q4nh69bQ2rI4+DNp22k0ZcxSL1Ljf19pe25Y6UgedrZf1sOLBVVDZxO36mxwUgPUqFp5/0nNmGMDdQeTQ=="
        )

        let p384Negative = Data(base64Encoded: "AiEfGE5ySReJyfSruLRdsjvCB5RNWGLk8JYrzIrans3MprXf5Q4nh69bQ2rI4+DNpw==")!
        let p384NegativeKey = try P384.KeyAgreement.PublicKey(compressedRepresentation: p384Negative)
        XCTAssertEqual(
            p384NegativeKey.x963Representation.base64EncodedString(),
            "BCEfGE5ySReJyfSruLRdsjvCB5RNWGLk8JYrzIrans3MprXf5Q4nh69bQ2rI4+DNp5JbLmjOt0K0cgKCWhJGnFrfhiUmgKTx0+qq8mOxIFZNPrfwrF6WGALYyZ508ivhsg=="
        )

        let p521Positive = Data(base64Encoded: "AwGUsatNKbCi6jeO1oFHpvhxesJnRxeZ45/sqCvaEZgwnpyj+/SsXjgBViEjvlJUdqentCaUFCwjuYZJM9HpdVq4Iw==")!
        let p521Key = try P521.KeyAgreement.PublicKey(compressedRepresentation: p521Positive)
        XCTAssertEqual(
            p521Key.x963Representation.base64EncodedString(),
            "BAGUsatNKbCi6jeO1oFHpvhxesJnRxeZ45/sqCvaEZgwnpyj+/SsXjgBViEjvlJUdqentCaUFCwjuYZJM9HpdVq4IwE8xEGqskayEkbPkQCGqSKfVYPZTkBdEs1ham1IXcqT4HSfoGGw98UwjQRiDPfIv0+vU6ocPbxURTdvwUSWPm72WQ=="
        )

        let p521Negative = Data(base64Encoded: "AgGUsatNKbCi6jeO1oFHpvhxesJnRxeZ45/sqCvaEZgwnpyj+/SsXjgBViEjvlJUdqentCaUFCwjuYZJM9HpdVq4Iw==")!
        let p521NegativeKey = try P521.KeyAgreement.PublicKey(compressedRepresentation: p521Negative)
        XCTAssertEqual(
            p521NegativeKey.x963Representation.base64EncodedString(),
            "BAGUsatNKbCi6jeO1oFHpvhxesJnRxeZ45/sqCvaEZgwnpyj+/SsXjgBViEjvlJUdqentCaUFCwjuYZJM9HpdVq4IwDDO75VTblN7bkwbv95Vt1gqnwmsb+i7TKelZK3ojVsH4tgX55PCDrPcvud8wg3QLBQrFXjwkOrusiQPrtpwZEJpg=="
        )
    }

    func testCompressedKeysUsingAPI() throws {
        let x963Positive = Data(base64Encoded: "A+QHCXtGd5WWSQgp37FBPXMy+nnSwFK79QQD0ZeNMv7L")!
        let key = try P256.KeyAgreement.PublicKey(compressedRepresentation: x963Positive)
        XCTAssertEqual(
            key.compressedRepresentation,
            x963Positive
        )

        let x963Negative = Data(base64Encoded: "AuQHCXtGd5WWSQgp37FBPXMy+nnSwFK79QQD0ZeNMv7L")!
        let negativeKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: x963Negative)
        XCTAssertEqual(
            negativeKey.compressedRepresentation,
            x963Negative
        )

        let p384Positive = Data(base64Encoded: "AyEfGE5ySReJyfSruLRdsjvCB5RNWGLk8JYrzIrans3MprXf5Q4nh69bQ2rI4+DNpw==")!
        let p384Key = try P384.KeyAgreement.PublicKey(compressedRepresentation: p384Positive)
        XCTAssertEqual(
            p384Key.compressedRepresentation,
            p384Positive
        )

        let p384Negative = Data(base64Encoded: "AiEfGE5ySReJyfSruLRdsjvCB5RNWGLk8JYrzIrans3MprXf5Q4nh69bQ2rI4+DNpw==")!
        let p384NegativeKey = try P384.KeyAgreement.PublicKey(compressedRepresentation: p384Negative)
        XCTAssertEqual(
            p384NegativeKey.compressedRepresentation,
            p384Negative
        )

        let p521Positive = Data(base64Encoded: "AwGUsatNKbCi6jeO1oFHpvhxesJnRxeZ45/sqCvaEZgwnpyj+/SsXjgBViEjvlJUdqentCaUFCwjuYZJM9HpdVq4Iw==")!
        let p521Key = try P521.KeyAgreement.PublicKey(compressedRepresentation: p521Positive)
        XCTAssertEqual(
            p521Key.compressedRepresentation,
            p521Positive
        )

        let p521Negative = Data(base64Encoded: "AgGUsatNKbCi6jeO1oFHpvhxesJnRxeZ45/sqCvaEZgwnpyj+/SsXjgBViEjvlJUdqentCaUFCwjuYZJM9HpdVq4Iw==")!
        let p521NegativeKey = try P521.KeyAgreement.PublicKey(compressedRepresentation: p521Negative)
        XCTAssertEqual(
            p521NegativeKey.compressedRepresentation,
            p521Negative
        )

        // Check that the uncompressed key gets rejected
        let uncompressedX963 = Data(base64Encoded: "BOQHCXtGd5WWSQgp37FBPXMy+nnSwFK79QQD0ZeNMv7LE6xvfFkB4Y3VXoOpB/Kp6ngpf3Lce9hDMl7fqaDUfYE=")!

        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(compressedRepresentation: uncompressedX963))
    }

    func testUncompressedKeys() throws {
        let uncompressedX963 = Data(base64Encoded: "BOQHCXtGd5WWSQgp37FBPXMy+nnSwFK79QQD0ZeNMv7LE6xvfFkB4Y3VXoOpB/Kp6ngpf3Lce9hDMl7fqaDUfYE=")!
        let key = try P256.KeyAgreement.PublicKey(x963Representation: uncompressedX963)
        XCTAssertEqual(
            key.x963Representation.base64EncodedString(),
            "BOQHCXtGd5WWSQgp37FBPXMy+nnSwFK79QQD0ZeNMv7LE6xvfFkB4Y3VXoOpB/Kp6ngpf3Lce9hDMl7fqaDUfYE="
        )

        let compressedX963Positive = Data(base64Encoded: "A+QHCXtGd5WWSQgp37FBPXMy+nnSwFK79QQD0ZeNMv7L")!
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(x963Representation: compressedX963Positive))
    }
    
    func testWycheproof() throws {
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "x25519_test",
                testFunction: { (group: ECDHTestGroup) in
                    try orFail { try testGroup(group: group) }
                })
        }
    }

    func testGroup(group: ECDHTestGroup) throws {
        for testVector in group.tests {
            let publicKey = try orFail { try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Array(hexString: testVector.publicKey)) }
            let privateKey = try orFail { try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Array(hexString: testVector.privateKey)) }

            do {
                let expectedSharedSecret = try Array(hexString: testVector.shared)

                let testSharedSecret = try Array(privateKey.sharedSecretFromKeyAgreement(with: publicKey).ss)
                XCTAssertEqual(testSharedSecret, expectedSharedSecret)
                XCTAssert(testVector.result == "valid" || testVector.result == "acceptable")
            } catch {
                if testVector.flags.contains("LowOrderPublic") {
                    XCTAssertEqual(testVector.result, "acceptable")
                    return
                }
                XCTAssertEqual(testVector.result, "invalid")
            }
        }
    }
}

#endif // CRYPTO_IN_SWIFTPM
