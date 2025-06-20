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

struct ECDSATestGroup: Codable {
    let tests: [SignatureTestVector]
    let publicKey: ECDSAKey
}

struct ECDSAKey: Codable {
    let uncompressed: String
}

struct SignatureTestVector: Codable {
    let comment: String
    let msg: String
    let sig: String
    let result: String
    let flags: [String]
    let tcId: Int
}

class SignatureTests: XCTestCase {
    let data = "Testing Signatures".data(using: String.Encoding.utf8)!
    
    func testWycheproofP256DER() throws {
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdsa_secp256r1_sha256_test",
                testFunction: { (group: ECDSATestGroup) in
                    try orFail { try testGroup(group: group, curve: P256.Signing.self, hashFunction: SHA256.self, deserializeSignature: P256.Signing.ECDSASignature.init(derRepresentation:)) }
                })
        }
        
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdsa_secp256r1_sha512_test",
                testFunction: { (group: ECDSATestGroup) in
                    try orFail { try testGroup(group: group, curve: P256.Signing.self, hashFunction: SHA512.self, deserializeSignature: P256.Signing.ECDSASignature.init(derRepresentation:)) }
                })
        }
    }
    
    func testWycheproofP384DER() throws {
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdsa_secp384r1_sha384_test",
                testFunction: { (group: ECDSATestGroup) in
                    try orFail { try testGroup(group: group, curve: P384.Signing.self, hashFunction: SHA384.self, deserializeSignature: P384.Signing.ECDSASignature.init(derRepresentation:)) }
                })
        }
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdsa_secp384r1_sha512_test",
                testFunction: { (group: ECDSATestGroup) in
                    try orFail { try testGroup(group: group, curve: P384.Signing.self, hashFunction: SHA512.self, deserializeSignature: P384.Signing.ECDSASignature.init(derRepresentation:)) }
                })
        }
    }
    
    func testWycheproofP521DER() throws {
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdsa_secp521r1_sha512_test",
                testFunction: { (group: ECDSATestGroup) in
                    try orFail { try testGroup(group: group, curve: P521.Signing.self, hashFunction: SHA512.self, deserializeSignature: P521.Signing.ECDSASignature.init(derRepresentation:)) }
                })
        }
    }

    func testWycheproofP256P1363() throws {
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdsa_secp256r1_sha256_p1363_test",
                testFunction: { (group: ECDSATestGroup) in
                    try orFail { try testGroup(group: group, curve: P256.Signing.self, hashFunction: SHA256.self, deserializeSignature: P256.Signing.ECDSASignature.init(rawRepresentation:)) }
                })
        }

        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdsa_secp256r1_sha512_p1363_test",
                testFunction: { (group: ECDSATestGroup) in
                    try orFail { try testGroup(group: group, curve: P256.Signing.self, hashFunction: SHA512.self, deserializeSignature: P256.Signing.ECDSASignature.init(rawRepresentation:)) }
                })
        }
    }

    func testWycheproofP384P1363() throws {
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdsa_secp384r1_sha384_p1363_test",
                testFunction: { (group: ECDSATestGroup) in
                    try orFail { try testGroup(group: group, curve: P384.Signing.self, hashFunction: SHA384.self, deserializeSignature: P384.Signing.ECDSASignature.init(rawRepresentation:)) }
                })
        }
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdsa_secp384r1_sha512_p1363_test",
                testFunction: { (group: ECDSATestGroup) in
                    try orFail { try testGroup(group: group, curve: P384.Signing.self, hashFunction: SHA512.self, deserializeSignature: P384.Signing.ECDSASignature.init(rawRepresentation:)) }
                })
        }
    }

    func testWycheproofP521P1363() throws {
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdsa_secp521r1_sha512_p1363_test",
                testFunction: { (group: ECDSATestGroup) in
                    try orFail { try testGroup(group: group, curve: P521.Signing.self, hashFunction: SHA512.self, deserializeSignature: P521.Signing.ECDSASignature.init(rawRepresentation:)) }
                })
        }
    }
    
    func testGroup<C: NISTSigning, HF: HashFunction>(group: ECDSATestGroup, curve: C.Type, hashFunction: HF.Type, deserializeSignature: (Data) throws -> C.ECDSASignature, file: StaticString = #filePath, line: UInt = #line) throws where C.ECDSASignature == C.PublicKey.Signature {
        let keyBytes = try orFail(file: file, line: line) { try Array(hexString: group.publicKey.uncompressed) }
        let key = try orFail(file: file, line: line) { try C.PublicKey(x963Representation: keyBytes) }

        for testVector in group.tests {
            if testVector.msg == "" {
                continue
            }

            var isValid = false

            do {
                let sig = try Data(hexString: testVector.sig)
                let msg = try Data(hexString: testVector.msg)

                let digest = HF.hash(data: msg)

                let signature = try deserializeSignature(sig)

                isValid = key.isValidSignature(signature, for: digest)
            } catch {
                XCTAssert(testVector.result == "invalid" || testVector.result == "acceptable", "Test ID: \(testVector.tcId) is valid, but failed \(error.localizedDescription).", file: file, line: line)
                continue
            }

            switch testVector.result {
            case "valid": XCTAssert(isValid, "Test vector is valid, but is rejected \(testVector.tcId)", file: file, line: line)
            case "acceptable": do {
                XCTAssert(isValid, file: file, line: line)
                }
            case "invalid": XCTAssert(!isValid, "Test ID: \(testVector.tcId) is valid, but failed.", file: file, line: line)
            default:
                XCTFail("Unhandled test vector", file: file, line: line)
            }
        }
    }

    func testP256Usage() throws {
        let signingKey = P256.Signing.PrivateKey()

        let signature = try orFail { try signingKey.signature(for: data) }

        XCTAssert(signingKey.publicKey.isValidSignature(signature, for: data))
    }

    func testP256Representations() throws {
        let signingKey = P256.Signing.PrivateKey()
        let signature = try orFail { try signingKey.signature(for: data) }
        XCTAssertEqual(signature.composite.r + signature.composite.s, signature.rawRepresentation)

        let signatureBytesFromPointer = signature.withUnsafeBytes { Data($0) }
        XCTAssertEqual(signature.rawRepresentation, signatureBytesFromPointer)

        let roundTrippedSignature = try orFail { try P256.Signing.ECDSASignature(derRepresentation: signature.derRepresentation) }
        XCTAssertEqual(signature.rawRepresentation, roundTrippedSignature.rawRepresentation)
    }

    func testP384Representations() throws {
        let signingKey = P384.Signing.PrivateKey()
        let signature = try orFail { try signingKey.signature(for: data) }
        XCTAssertEqual(signature.composite.r + signature.composite.s, signature.rawRepresentation)

        let signatureBytesFromPointer = signature.withUnsafeBytes { Data($0) }
        XCTAssertEqual(signature.rawRepresentation, signatureBytesFromPointer)

        let roundTrippedSignature = try orFail { try P384.Signing.ECDSASignature(derRepresentation: signature.derRepresentation) }
        XCTAssertEqual(signature.rawRepresentation, roundTrippedSignature.rawRepresentation)
    }

    func testP521Representations() throws {
        let signingKey = P521.Signing.PrivateKey()
        let signature = try orFail { try signingKey.signature(for: data) }
        XCTAssertEqual(signature.composite.r + signature.composite.s, signature.rawRepresentation)

        let signatureBytesFromPointer = signature.withUnsafeBytes { Data($0) }
        XCTAssertEqual(signature.rawRepresentation, signatureBytesFromPointer)

        let roundTrippedSignature = try orFail { try P521.Signing.ECDSASignature(derRepresentation: signature.derRepresentation) }
        XCTAssertEqual(signature.rawRepresentation, roundTrippedSignature.rawRepresentation)
    }

    func testProperSignatureSizes() throws {
        XCTAssertThrowsError(try P256.Signing.ECDSASignature(rawRepresentation: Array("hello".utf8)),
                             error: CryptoKitError.incorrectParameterSize)
        XCTAssertThrowsError(try P384.Signing.ECDSASignature(rawRepresentation: Array("hello".utf8)),
                             error: CryptoKitError.incorrectParameterSize)
        XCTAssertThrowsError(try P521.Signing.ECDSASignature(rawRepresentation: Array("hello".utf8)),
                             error: CryptoKitError.incorrectParameterSize)
    }

    func testP256SigningDiscontiguousData() throws {
        let signingKey = P256.Signing.PrivateKey()

        // We generate 4 signatures here, all of which should be identical. We validate them all, which means there is a lot of validating here:
        // 8 in total.
        let (contiguousData, discontiguousData) = Array(data).asDataProtocols()
        let (contiguousContiguous, discontiguousContiguous) = try orFail { Array(try signingKey.signature(for: contiguousData).derRepresentation).asDataProtocols() }
        let (contiguousDiscontiguous, discontiguousDiscontiguous) = try orFail { Array(try signingKey.signature(for: discontiguousData).derRepresentation).asDataProtocols() }

        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousContiguous), for: contiguousData))
        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousContiguous), for: contiguousData))
        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousDiscontiguous), for: contiguousData))
        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousDiscontiguous), for: contiguousData))
        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousContiguous), for: discontiguousData))
        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousContiguous), for: discontiguousData))
        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousDiscontiguous), for: discontiguousData))
        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousDiscontiguous), for: discontiguousData))

        // While we're here, let's confirm that we can also reject this appropriately.
        let anotherKey = P256.Signing.PrivateKey()
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousContiguous), for: contiguousData))
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousContiguous), for: contiguousData))
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousDiscontiguous), for: contiguousData))
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousDiscontiguous), for: contiguousData))
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousContiguous), for: discontiguousData))
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousContiguous), for: discontiguousData))
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousDiscontiguous), for: discontiguousData))
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousDiscontiguous), for: discontiguousData))
    }

    func testP384SigningDiscontiguousData() throws {
        let signingKey = P384.Signing.PrivateKey()

        // We generate 4 signatures here, all of which should be identical. We validate them all, which means there is a lot of validating here:
        // 8 in total.
        let (contiguousData, discontiguousData) = Array(data).asDataProtocols()
        let (contiguousContiguous, discontiguousContiguous) = try orFail { Array(try signingKey.signature(for: contiguousData).derRepresentation).asDataProtocols() }
        let (contiguousDiscontiguous, discontiguousDiscontiguous) = try orFail { Array(try signingKey.signature(for: discontiguousData).derRepresentation).asDataProtocols() }

        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousContiguous), for: contiguousData))
        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousContiguous), for: contiguousData))
        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousDiscontiguous), for: contiguousData))
        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousDiscontiguous), for: contiguousData))
        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousContiguous), for: discontiguousData))
        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousContiguous), for: discontiguousData))
        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousDiscontiguous), for: discontiguousData))
        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousDiscontiguous), for: discontiguousData))

        // While we're here, let's confirm that we can also reject this appropriately.
        let anotherKey = P384.Signing.PrivateKey()
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousContiguous), for: contiguousData))
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousContiguous), for: contiguousData))
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousDiscontiguous), for: contiguousData))
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousDiscontiguous), for: contiguousData))
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousContiguous), for: discontiguousData))
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousContiguous), for: discontiguousData))
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousDiscontiguous), for: discontiguousData))
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousDiscontiguous), for: discontiguousData))
    }

    func testP521SigningDiscontiguousData() throws {
        let signingKey = P521.Signing.PrivateKey()

        // We generate 4 signatures here, all of which should be identical. We validate them all, which means there is a lot of validating here:
        // 8 in total.
        let (contiguousData, discontiguousData) = Array(data).asDataProtocols()
        let (contiguousContiguous, discontiguousContiguous) = try orFail { Array(try signingKey.signature(for: contiguousData).derRepresentation).asDataProtocols() }
        let (contiguousDiscontiguous, discontiguousDiscontiguous) = try orFail { Array(try signingKey.signature(for: discontiguousData).derRepresentation).asDataProtocols() }

        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousContiguous), for: contiguousData))
        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousContiguous), for: contiguousData))
        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousDiscontiguous), for: contiguousData))
        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousDiscontiguous), for: contiguousData))
        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousContiguous), for: discontiguousData))
        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousContiguous), for: discontiguousData))
        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousDiscontiguous), for: discontiguousData))
        XCTAssertTrue(signingKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousDiscontiguous), for: discontiguousData))

        // While we're here, let's confirm that we can also reject this appropriately.
        let anotherKey = P521.Signing.PrivateKey()
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousContiguous), for: contiguousData))
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousContiguous), for: contiguousData))
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousDiscontiguous), for: contiguousData))
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousDiscontiguous), for: contiguousData))
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousContiguous), for: discontiguousData))
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousContiguous), for: discontiguousData))
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: contiguousDiscontiguous), for: discontiguousData))
        XCTAssertFalse(anotherKey.publicKey.isValidSignature(try .init(derRepresentation: discontiguousDiscontiguous), for: discontiguousData))
    }

    func testCompressedKeys() throws {
        let x963Positive = Data(base64Encoded: "A+QHCXtGd5WWSQgp37FBPXMy+nnSwFK79QQD0ZeNMv7L")!
        let key = try P256.Signing.PublicKey(compressedRepresentation: x963Positive)
        XCTAssertEqual(
            key.x963Representation.base64EncodedString(),
            "BOQHCXtGd5WWSQgp37FBPXMy+nnSwFK79QQD0ZeNMv7LE6xvfFkB4Y3VXoOpB/Kp6ngpf3Lce9hDMl7fqaDUfYE="
        )

        let x963Negative = Data(base64Encoded: "AuQHCXtGd5WWSQgp37FBPXMy+nnSwFK79QQD0ZeNMv7L")!
        let negativeKey = try P256.Signing.PublicKey(compressedRepresentation: x963Negative)
        XCTAssertEqual(
            negativeKey.x963Representation.base64EncodedString(),
            "BOQHCXtGd5WWSQgp37FBPXMy+nnSwFK79QQD0ZeNMv7L7FOQgqb+HnMqoXxW+A1WFYfWgI4jhCe8zaEgVl8rgn4="
        )

        let p384Positive = Data(base64Encoded: "AyEfGE5ySReJyfSruLRdsjvCB5RNWGLk8JYrzIrans3MprXf5Q4nh69bQ2rI4+DNpw==")!
        let p384Key = try P384.Signing.PublicKey(compressedRepresentation: p384Positive)
        XCTAssertEqual(
            p384Key.x963Representation.base64EncodedString(),
            "BCEfGE5ySReJyfSruLRdsjvCB5RNWGLk8JYrzIrans3MprXf5Q4nh69bQ2rI4+DNp22k0ZcxSL1Ljf19pe25Y6UgedrZf1sOLBVVDZxO36mxwUgPUqFp5/0nNmGMDdQeTQ=="
        )

        let p384Negative = Data(base64Encoded: "AiEfGE5ySReJyfSruLRdsjvCB5RNWGLk8JYrzIrans3MprXf5Q4nh69bQ2rI4+DNpw==")!
        let p384NegativeKey = try P384.Signing.PublicKey(compressedRepresentation: p384Negative)
        XCTAssertEqual(
            p384NegativeKey.x963Representation.base64EncodedString(),
            "BCEfGE5ySReJyfSruLRdsjvCB5RNWGLk8JYrzIrans3MprXf5Q4nh69bQ2rI4+DNp5JbLmjOt0K0cgKCWhJGnFrfhiUmgKTx0+qq8mOxIFZNPrfwrF6WGALYyZ508ivhsg=="
        )

        let p521Positive = Data(base64Encoded: "AwGUsatNKbCi6jeO1oFHpvhxesJnRxeZ45/sqCvaEZgwnpyj+/SsXjgBViEjvlJUdqentCaUFCwjuYZJM9HpdVq4Iw==")!
        let p521Key = try P521.Signing.PublicKey(compressedRepresentation: p521Positive)
        XCTAssertEqual(
            p521Key.x963Representation.base64EncodedString(),
            "BAGUsatNKbCi6jeO1oFHpvhxesJnRxeZ45/sqCvaEZgwnpyj+/SsXjgBViEjvlJUdqentCaUFCwjuYZJM9HpdVq4IwE8xEGqskayEkbPkQCGqSKfVYPZTkBdEs1ham1IXcqT4HSfoGGw98UwjQRiDPfIv0+vU6ocPbxURTdvwUSWPm72WQ=="
        )

        let p521Negative = Data(base64Encoded: "AgGUsatNKbCi6jeO1oFHpvhxesJnRxeZ45/sqCvaEZgwnpyj+/SsXjgBViEjvlJUdqentCaUFCwjuYZJM9HpdVq4Iw==")!
        let p521NegativeKey = try P521.Signing.PublicKey(compressedRepresentation: p521Negative)
        XCTAssertEqual(
            p521NegativeKey.x963Representation.base64EncodedString(),
            "BAGUsatNKbCi6jeO1oFHpvhxesJnRxeZ45/sqCvaEZgwnpyj+/SsXjgBViEjvlJUdqentCaUFCwjuYZJM9HpdVq4IwDDO75VTblN7bkwbv95Vt1gqnwmsb+i7TKelZK3ojVsH4tgX55PCDrPcvud8wg3QLBQrFXjwkOrusiQPrtpwZEJpg=="
        )

        // Check that the uncompressed key gets rejected
        let uncompressedX963 = Data(base64Encoded: "BOQHCXtGd5WWSQgp37FBPXMy+nnSwFK79QQD0ZeNMv7LE6xvfFkB4Y3VXoOpB/Kp6ngpf3Lce9hDMl7fqaDUfYE=")!

        XCTAssertThrowsError(try P256.Signing.PublicKey(compressedRepresentation: uncompressedX963))
    }

    func testUncompressedKeys() throws {
        let uncompressedX963 = Data(base64Encoded: "BOQHCXtGd5WWSQgp37FBPXMy+nnSwFK79QQD0ZeNMv7LE6xvfFkB4Y3VXoOpB/Kp6ngpf3Lce9hDMl7fqaDUfYE=")!
        let key = try P256.Signing.PublicKey(x963Representation: uncompressedX963)
        XCTAssertEqual(
            key.x963Representation.base64EncodedString(),
            "BOQHCXtGd5WWSQgp37FBPXMy+nnSwFK79QQD0ZeNMv7LE6xvfFkB4Y3VXoOpB/Kp6ngpf3Lce9hDMl7fqaDUfYE="
        )

        let compressedX963Positive = Data(base64Encoded: "A+QHCXtGd5WWSQgp37FBPXMy+nnSwFK79QQD0ZeNMv7L")!
        XCTAssertThrowsError(try P256.Signing.PublicKey(x963Representation: compressedX963Positive))
    }
    
}
#endif // CRYPTO_IN_SWIFTPM
