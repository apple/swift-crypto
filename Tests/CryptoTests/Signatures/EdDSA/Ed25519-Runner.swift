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
import Crypto
#elseif !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
import CryptoKit
#else
import Crypto
#endif

struct Ed25519TestGroup: Codable {
    let tests: [Ed25519TestVector]
    let publicKey: Ed25519PublicKey
}

struct Ed25519PublicKey: Codable {
    let pk: String
}

struct Ed25519TestVector: Codable {
    let comment: String
    let msg: String
    let sig: String
    let result: String
    let flags: [String]
    let tcId: Int
}

class Ed25519Tests: XCTestCase {
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
        #if !canImport(Darwin)
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

    func testWycheProof() throws {
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ed25519_test",
                testFunction: { (group: Ed25519TestGroup) in
                    try orFail { try testGroup(group: group) }
                })
        }
    }

    func testGroup(group: Ed25519TestGroup, file: StaticString = #filePath, line: UInt = #line) throws {
        let keyBytes = try orFail { try Array(hexString: group.publicKey.pk) }
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
}
