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

final class MLKEMKeyGenTests: XCTestCase {
    func processKeyGenKATFile(filename: String) throws -> [MLKEMKeyGenKAT] {
        #if CRYPTO_IN_SWIFTPM
        let bundle = Bundle.module
        #else
        let bundle = Bundle(for: type(of: self))
        #endif
        let fileURL = bundle.url(forResource: filename, withExtension: "json")
        let json = try Data(contentsOf: fileURL!)
        let stringInput = String(data: json, encoding: .ascii)!
        let tests = try JSONDecoder().decode([MLKEMKeyGenKATHex].self, from: stringInput.data(using: .ascii)!)
        return try tests.map { try MLKEMKeyGenKAT($0) }
    }

    func test768KAT() throws {
        let katTests = try processKeyGenKATFile(filename:"MLKEM768_BSSLKAT")
        for katTest in katTests {
            let publicKey = try MLKEM768.PublicKey(rawRepresentation: katTest.pk)
            let privateKey = try MLKEM768.PrivateKey(seedRepresentation: katTest.dz, publicKey: publicKey)
            let publicKeyHash = Data(SHA3_256.hash(data: privateKey.publicKey.rawRepresentation))

            XCTAssert(privateKey.seedRepresentation == katTest.dz)
            XCTAssert(privateKey.integrityCheckedRepresentation == katTest.dz + publicKeyHash)
            XCTAssert(privateKey.publicKey.rawRepresentation == katTest.pk)

            // Try initializing keys with incorrect integrity checks
            let randomPrivateKey = try MLKEM768.PrivateKey.generate()
            let randomPublicKeyHash = Data(SHA3_256.hash(data: randomPrivateKey.publicKey.rawRepresentation))
            XCTAssertThrowsError(try MLKEM768.PrivateKey(seedRepresentation: privateKey.seedRepresentation, publicKey: randomPrivateKey.publicKey), error: KEM.Errors.publicKeyMismatchDuringInitialization)
            XCTAssertThrowsError(try MLKEM768.PrivateKey(seedRepresentation: randomPrivateKey.seedRepresentation, publicKey: publicKey), error: KEM.Errors.publicKeyMismatchDuringInitialization)
            XCTAssertThrowsError(try MLKEM768.PrivateKey(integrityCheckedRepresentation: privateKey.seedRepresentation + randomPublicKeyHash), error: KEM.Errors.publicKeyMismatchDuringInitialization)
            XCTAssertThrowsError(try MLKEM768.PrivateKey(integrityCheckedRepresentation: randomPrivateKey.seedRepresentation + publicKeyHash), error: KEM.Errors.publicKeyMismatchDuringInitialization)
        }

    }

    func test1024KAT() throws {
        let katTests = try processKeyGenKATFile(filename:"MLKEM1024_BSSLKAT")
        for katTest in katTests {
            let publicKey = try MLKEM1024.PublicKey(rawRepresentation: katTest.pk)
            let privateKey = try MLKEM1024.PrivateKey(seedRepresentation: katTest.dz, publicKey: publicKey)
            let publicKeyHash = Data(SHA3_256.hash(data: privateKey.publicKey.rawRepresentation))

            XCTAssert(privateKey.seedRepresentation == katTest.dz)
            XCTAssert(privateKey.integrityCheckedRepresentation == katTest.dz + publicKeyHash)
            XCTAssert(privateKey.publicKey.rawRepresentation == katTest.pk)

            // Try initializing keys with incorrect integrity checks
            let randomPrivateKey = try MLKEM1024.PrivateKey.generate()
            let randomPublicKeyHash = Data(SHA3_256.hash(data: randomPrivateKey.publicKey.rawRepresentation))
            XCTAssertThrowsError(try MLKEM1024.PrivateKey(seedRepresentation: privateKey.seedRepresentation, publicKey: randomPrivateKey.publicKey), error: KEM.Errors.publicKeyMismatchDuringInitialization)
            XCTAssertThrowsError(try MLKEM1024.PrivateKey(seedRepresentation: randomPrivateKey.seedRepresentation, publicKey: publicKey), error: KEM.Errors.publicKeyMismatchDuringInitialization)
            XCTAssertThrowsError(try MLKEM1024.PrivateKey(integrityCheckedRepresentation: privateKey.seedRepresentation + randomPublicKeyHash), error: KEM.Errors.publicKeyMismatchDuringInitialization)
            XCTAssertThrowsError(try MLKEM1024.PrivateKey(integrityCheckedRepresentation: randomPrivateKey.seedRepresentation + publicKeyHash), error: KEM.Errors.publicKeyMismatchDuringInitialization)
        }
    }
}

// Struct to parse KAT file
struct MLKEMKeyGenKATHex: Codable {
    var dz: String
    var pk: String
    var sk: String
}

// Represent KAT with Data
struct MLKEMKeyGenKAT {
    var dz: Data
    var pk: Data
    var sk: Data
    init(_ hexRep: MLKEMKeyGenKATHex) throws {
        dz = try Data(hexString: hexRep.dz)
        pk = try Data(hexString: hexRep.pk)
        sk = try Data(hexString: hexRep.sk)
    }
}

#endif // CRYPTO_IN_SWIFTPM
