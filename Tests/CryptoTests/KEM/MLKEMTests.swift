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

final class MLKEMTests: XCTestCase {
    func testMLKEM768() throws {
        let privateKey = try MLKEM768.PrivateKey.generate()
        let publicKey = privateKey.publicKey

        // Test Public Key Serialization
        try XCTAssert(publicKey.rawRepresentation == MLKEM768.PublicKey(rawRepresentation: publicKey.rawRepresentation).rawRepresentation)

        // Test Private Key serialization
        try XCTAssert(privateKey.seedRepresentation == MLKEM768.PrivateKey(seedRepresentation: privateKey.seedRepresentation, publicKey: publicKey).seedRepresentation)
        try XCTAssert(privateKey.integrityCheckedRepresentation == MLKEM768.PrivateKey(integrityCheckedRepresentation: privateKey.integrityCheckedRepresentation).integrityCheckedRepresentation)

        let er = try publicKey.encapsulate()
        let ss = try privateKey.decapsulate(er.encapsulated)

        XCTAssert(er.sharedSecret == ss)
    }

    func testMLKEM1024() throws {
        let privateKey = try MLKEM1024.PrivateKey.generate()
        let publicKey = privateKey.publicKey

        // Test Public Key Serialization
        try XCTAssert(publicKey.rawRepresentation == MLKEM1024.PublicKey(rawRepresentation: publicKey.rawRepresentation).rawRepresentation)

        // Test Private Key serialization
        try XCTAssert(privateKey.seedRepresentation == MLKEM1024.PrivateKey(seedRepresentation: privateKey.seedRepresentation, publicKey: publicKey).seedRepresentation)
        try XCTAssert(privateKey.integrityCheckedRepresentation == MLKEM1024.PrivateKey(integrityCheckedRepresentation: privateKey.integrityCheckedRepresentation).integrityCheckedRepresentation)

        let er = try publicKey.encapsulate()
        let ss = try privateKey.decapsulate(er.encapsulated)

        XCTAssert(er.sharedSecret == ss)
    }

    func processKATFile(filename: String) throws -> [MLKEMKAT] {
        #if CRYPTO_IN_SWIFTPM
        let bundle = Bundle.module
        #else
        let bundle = Bundle(for: type(of: self))
        #endif
        let fileURL = bundle.url(forResource: filename, withExtension: "json")
        let json = try Data(contentsOf: fileURL!)
        let stringInput = String(data: json, encoding: .ascii)!
        let tests = try JSONDecoder().decode([MLKEMKATHex].self, from: stringInput.data(using: .ascii)!)
        return try tests.map { try MLKEMKAT($0) }
    }

    func test768KAT() throws {
        #if CRYPTO_IN_SWIFTPM
        // No support for encapsulateWithSeed in BoringSSL.
        throw XCTSkip()
        #else
        let katTests = try processKATFile(filename:"MLKEM768KAT")
        for katTest in katTests {
            let rndGen = try Drbg(katTest.rngSeed)

            var keyGenSeed = Data(count: 64)
            try keyGenSeed.withUnsafeMutableBytes { buffer in
                try buffer.initializeWithRandomBytes(count: buffer.count, rngState: rndGen)
            }
            var encapSeed = Data(count: 32)
            try encapSeed.withUnsafeMutableBytes { buffer in
                try buffer.initializeWithRandomBytes(count: buffer.count, rngState: rndGen)
            }

            let privateKey = try MLKEM768.PrivateKey.generateWithSeed(keyGenSeed) // 2 * 32 bytes
            XCTAssert(privateKey.publicKey.rawRepresentation == katTest.pk)

            let encapsulatedKey = try privateKey.publicKey.encapsulateWithSeed(encapSeed: encapSeed) // 32 bytes
            XCTAssert(encapsulatedKey.encapsulated == katTest.ek)
            XCTAssert(encapsulatedKey.sharedSecret == katTest.k)

            let retrievedSharedSecret = try privateKey.decapsulate(encapsulatedKey.encapsulated)
            XCTAssert(retrievedSharedSecret.dataRepresentation == katTest.k)
        }
        #endif
    }

    func test1024KAT() throws {
        #if CRYPTO_IN_SWIFTPM
        // No support for encapsulateWithSeed in BoringSSL.
        throw XCTSkip()
        #else
        let katTests = try processKATFile(filename:"MLKEM1024KAT")
        for katTest in katTests {
            let rndGen = try Drbg(katTest.rngSeed)

            var keyGenSeed = Data(count: 64)
            try keyGenSeed.withUnsafeMutableBytes { buffer in
                try buffer.initializeWithRandomBytes(count: buffer.count, rngState: rndGen)
            }
            var encapSeed = Data(count: 32)
            try encapSeed.withUnsafeMutableBytes { buffer in
                try buffer.initializeWithRandomBytes(count: buffer.count, rngState: rndGen)
            }

            let privateKey = try MLKEM1024.PrivateKey.generateWithSeed(keyGenSeed)
            XCTAssert(privateKey.publicKey.rawRepresentation == katTest.pk)

            let encapsulatedKey = try privateKey.publicKey.encapsulateWithSeed(encapSeed: encapSeed)
            XCTAssert(encapsulatedKey.encapsulated == katTest.ek)
            XCTAssert(encapsulatedKey.sharedSecret == katTest.k)

            let retrievedSharedSecret = try privateKey.decapsulate(encapsulatedKey.encapsulated)
            XCTAssert(retrievedSharedSecret.dataRepresentation == katTest.k)
        }
        #endif
    }
}

// Struct to parse KAT file
struct MLKEMKATHex: Codable {
    var rngSeed: String
    var sk: String
    var pk: String
    var ek: String
    var k: String
}

// Represent KAT with Data
struct MLKEMKAT {
    var rngSeed: Data
    var sk: Data
    var pk: Data
    var ek: Data
    var k: Data
    init(_ hexRep: MLKEMKATHex) throws {
        rngSeed = try Data(hexString: hexRep.rngSeed)
        sk = try Data(hexString: hexRep.sk)
        pk = try Data(hexString: hexRep.pk)
        ek = try Data(hexString: hexRep.ek)
        k = try Data(hexString: hexRep.k)
    }
}

#endif // CRYPTO_IN_SWIFTPM
