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

final class XWingTests: XCTestCase {
    func testKEM() throws {
        let privateKey = try XWingMLKEM768X25519.PrivateKey.generate()

        let publicKey = privateKey.publicKey

        try XCTAssert(publicKey.rawRepresentation == XWingMLKEM768X25519.PublicKey(rawRepresentation: publicKey.rawRepresentation).rawRepresentation)
        try XCTAssert(privateKey.seedRepresentation == XWingMLKEM768X25519.PrivateKey(seedRepresentation: privateKey.seedRepresentation, publicKey: nil).seedRepresentation)
        try XCTAssert(privateKey.seedRepresentation == XWingMLKEM768X25519.PrivateKey(seedRepresentation: privateKey.seedRepresentation, publicKey: publicKey).seedRepresentation)
        try XCTAssert(privateKey.integrityCheckedRepresentation == XWingMLKEM768X25519.PrivateKey(integrityCheckedRepresentation: privateKey.integrityCheckedRepresentation).integrityCheckedRepresentation)

        let er = try privateKey.publicKey.encapsulate()
        let ss = try privateKey.decapsulate(er.encapsulated)

        XCTAssert(er.sharedSecret == ss)
    }

    func processKATFile(filename: String) throws -> [XWingKAT] {
        #if CRYPTO_IN_SWIFTPM
        let bundle = Bundle.module
        #else
        let bundle = Bundle(for: type(of: self))
        #endif
        let fileURL = bundle.url(forResource: filename, withExtension: "json")
        let json = try Data(contentsOf: fileURL!)
        let stringInput = String(data: json, encoding: .ascii)!
        let tests = try JSONDecoder().decode([XWingKATHex].self, from: stringInput.data(using: .ascii)!)
        return try tests.map { try XWingKAT($0) }
    }

    func testXWingMLKEM768X25519TestVectors() throws {
        let katTests = try processKATFile(filename:"test-vectors")
        for katTest in katTests {
            let privateKeyDrbg = try SequenceDrbg(katTest.seed)
            let privateKey = try XWingMLKEM768X25519.PrivateKey.generateWithRng(rngState: privateKeyDrbg)
            XCTAssertEqual(privateKey.publicKey.rawRepresentation, katTest.pk)

            let encapDrbg = try SequenceDrbg(katTest.eseed)
            let encapsulatedKey = try privateKey.publicKey.encapsulateWithRng(rngState: encapDrbg)
            XCTAssertEqual(encapsulatedKey.encapsulated, katTest.ct)
            XCTAssertEqual(encapsulatedKey.sharedSecret.dataRepresentation, katTest.ss)
            let retrievedSharedSecret = try privateKey.decapsulate(encapsulatedKey.encapsulated)
            XCTAssertEqual(retrievedSharedSecret.dataRepresentation, katTest.ss)
        }
    }

    func testPrivateKeyRepresentations() throws {
        let privateKey = try XWingMLKEM768X25519.PrivateKey.generate()
        XCTAssertEqual(privateKey.seedRepresentation.count, 32)
        XCTAssertEqual(privateKey.integrityCheckedRepresentation.count, 64)
        XCTAssertEqual(privateKey.integrityCheckedRepresentation.dropLast(32), privateKey.seedRepresentation)

        let recoveredPrivateKey = try XWingMLKEM768X25519.PrivateKey(seedRepresentation: privateKey.seedRepresentation, publicKeyHash: nil)
        XCTAssertNotNil(recoveredPrivateKey)
        XCTAssertEqual(recoveredPrivateKey.integrityCheckedRepresentation, privateKey.integrityCheckedRepresentation)

        let otherKey = try XWingMLKEM768X25519.PrivateKey.generate()
        XCTAssertThrowsError(try XWingMLKEM768X25519.PrivateKey(seedRepresentation: privateKey.seedRepresentation, publicKeyHash: SHA3_256.hash(data: otherKey.publicKey.rawRepresentation)), error: KEM.Errors.publicKeyMismatchDuringInitialization)

        let exportedFormat = privateKey.integrityCheckedRepresentation
        let importedKey = try XWingMLKEM768X25519.PrivateKey.init(integrityCheckedRepresentation: exportedFormat)
        XCTAssertEqual(importedKey.seedRepresentation, privateKey.seedRepresentation)
    }
}

// Struct to parse KAT file
struct XWingKATHex: Codable {
    var seed: String
    var sk: String
    var pk: String
    var eseed: String
    var ct: String
    var ss: String
}

// Represent KAT with Data
struct XWingKAT {
    var seed: Data
    var sk: Data
    var pk: Data
    var eseed: Data
    var ct: Data
    var ss: Data
    init(_ hexRep: XWingKATHex) throws {
        seed = try Data(hexString: hexRep.seed)
        sk = try Data(hexString: hexRep.sk)
        pk = try Data(hexString: hexRep.pk)
        eseed = try Data(hexString: hexRep.eseed)
        ct = try Data(hexString: hexRep.ct)
        ss = try Data(hexString: hexRep.ss)
    }
}

#endif // CRYPTO_IN_SWIFTPM
