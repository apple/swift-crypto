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
import Foundation
import XCTest

#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// Skip tests that require @testable imports of CryptoKit.
#else
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@testable import CryptoKit
#else
@testable import Crypto
#endif

struct ECDSATestGroup: Codable {
    let tests: [SignatureTestVector]
    let key: ECDSAKey
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

struct EdDSATestGroup: Codable {
    let tests: [SignatureTestVector]
    let key: EdDSAKey
}

struct EdDSAKey: Codable {
    let pk: String
}

class SignatureTests: XCTestCase {
    let data = "Testing Signatures".data(using: String.Encoding.utf8)!
    
    func testWycheProofEdDSA() throws {
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "eddsa_test",
                testFunction: { (group: EdDSATestGroup) in
                    try orFail { try testEdGroup(group: group) }
                })
        }
    }
    func testWycheProofP256() throws {
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdsa_secp256r1_sha256_test",
                testFunction: { (group: ECDSATestGroup) in
                    try orFail { try testGroup(group: group, curve: P256.Signing.self, hashFunction: SHA256.self) }
                })
        }
        
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdsa_secp256r1_sha512_test",
                testFunction: { (group: ECDSATestGroup) in
                    try orFail { try testGroup(group: group, curve: P256.Signing.self, hashFunction: SHA512.self) }
                })
        }
    }
    
    func testWycheProofP384() throws {
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdsa_secp384r1_sha384_test",
                testFunction: { (group: ECDSATestGroup) in
                    try orFail { try testGroup(group: group, curve: P384.Signing.self, hashFunction: SHA384.self) }
                })
        }
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdsa_secp384r1_sha512_test",
                testFunction: { (group: ECDSATestGroup) in
                    try orFail { try testGroup(group: group, curve: P384.Signing.self, hashFunction: SHA512.self) }
                })
        }
    }
    
    func testWycheProofP521() throws {
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdsa_secp521r1_sha512_test",
                testFunction: { (group: ECDSATestGroup) in
                    try orFail { try testGroup(group: group, curve: P521.Signing.self, hashFunction: SHA512.self) }
                })
        }
    }
    
    func testEdGroup(group: EdDSATestGroup, file: StaticString = #file, line: UInt = #line) throws {
        let keyBytes = try orFail { try Array(hexString: group.key.pk) }
        let key = try orFail { try Curve25519.Signing.PublicKey(rawRepresentation: keyBytes) }
        
        for testVector in group.tests {
            var isValid = false
            
            do {
                let sig = try Data(hexString: testVector.sig)
                
                let msg: Data
                if testVector.msg.count > 0 {
                    msg = try Data(hexString: testVector.msg)
                } else {
                    msg = Data()
                }
                
                isValid = key.isValidSignature(sig, for: msg)
            } catch {
                XCTAssert(testVector.result == "invalid" || testVector.result == "acceptable", "Test ID: \(testVector.tcId) is valid, but failed \(error.localizedDescription).")
                continue
            }
            
            switch testVector.result {
            case "valid": XCTAssert(isValid, "Test vector is valid, but is rejected \(testVector.tcId)")
            case "acceptable": do {
                XCTAssert(isValid)
                }
            case "invalid": XCTAssert(!isValid, "Test ID: \(testVector.tcId) is valid, but failed.")
            default:
                XCTFail("Unhandled test vector")
            }
        }
    }
    
    func testGroup<C: NISTSigning, HF: HashFunction>(group: ECDSATestGroup, curve: C.Type, hashFunction: HF.Type, file: StaticString = #file, line: UInt = #line) throws where C.ECDSASignature == C.PublicKey.Signature {
        let keyBytes = try orFail(file: file, line: line) { try Array(hexString: group.key.uncompressed) }
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

                let signature = try C.ECDSASignature(derRepresentation: sig)

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
        XCTAssertThrowsError(try P256.Signing.ECDSASignature(rawRepresentation: Array("hello".utf8))) { error in
            guard case .some(.incorrectParameterSize) = error as? CryptoKitError else {
                XCTFail("Incorrect error: \(error)")
                return
            }
        }

        XCTAssertThrowsError(try P384.Signing.ECDSASignature(rawRepresentation: Array("hello".utf8))) { error in
            guard case .some(.incorrectParameterSize) = error as? CryptoKitError else {
                XCTFail("Incorrect error: \(error)")
                return
            }
        }

        XCTAssertThrowsError(try P521.Signing.ECDSASignature(rawRepresentation: Array("hello".utf8))) { error in
            guard case .some(.incorrectParameterSize) = error as? CryptoKitError else {
                XCTFail("Incorrect error: \(error)")
                return
            }
        }
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
}
#endif // (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM
