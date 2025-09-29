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

final class MLDSAKeyGenTests: XCTestCase {
    func processKeyGenKATFile(filename: String) throws -> [MLDSAKeyGenKAT] {
        #if CRYPTO_IN_SWIFTPM
        let bundle = Bundle.module
        #else
        let bundle = Bundle(for: type(of: self))
        #endif
        let fileURL = bundle.url(forResource: filename, withExtension: "json")
        let json = try Data(contentsOf: fileURL!)
        let stringInput = String(data: json, encoding: .ascii)!
        let tests = try JSONDecoder().decode([MLDSAKeyGenKATHex].self, from: stringInput.data(using: .ascii)!)
        return try tests.map { try MLDSAKeyGenKAT($0) }
    }

    func test65KAT() throws {
        let katTests = try processKeyGenKATFile(filename: "MLDSA65_KeyGen_KAT")
        for katTest in katTests {
            let publicKey = try MLDSA65.PublicKey(rawRepresentation: katTest.pk)
            let privateKey = try MLDSA65.PrivateKey(seedRepresentation: katTest.seed, publicKey: publicKey)
            let publicKeyHash = Data(SHA3_256.hash(data: privateKey.publicKey.rawRepresentation))

            XCTAssert(privateKey.seedRepresentation == katTest.seed)
            XCTAssert(privateKey.integrityCheckedRepresentation == katTest.seed + publicKeyHash)
            XCTAssert(privateKey.publicKey.rawRepresentation == katTest.pk)

            // Try initializing keys with incorrect integrity checks
            let randomPrivateKey = try MLDSA65.PrivateKey()
            let randomPublicKeyHash = Data(SHA3_256.hash(data: randomPrivateKey.publicKey.rawRepresentation))
            XCTAssertThrowsError(try MLDSA65.PrivateKey(seedRepresentation: privateKey.seedRepresentation, publicKey: randomPrivateKey.publicKey), error: CryptoKitError.unwrapFailure)
            XCTAssertThrowsError(try MLDSA65.PrivateKey(seedRepresentation: randomPrivateKey.seedRepresentation, publicKey: publicKey), error: CryptoKitError.unwrapFailure)
            XCTAssertThrowsError(try MLDSA65.PrivateKey(integrityCheckedRepresentation: privateKey.seedRepresentation + randomPublicKeyHash), error: CryptoKitError.unwrapFailure)
            XCTAssertThrowsError(try MLDSA65.PrivateKey(integrityCheckedRepresentation: randomPrivateKey.seedRepresentation + publicKeyHash), error: CryptoKitError.unwrapFailure)
        }
    }

    func test87KAT() throws {
        let katTests = try processKeyGenKATFile(filename: "MLDSA87_KeyGen_KAT")
        for katTest in katTests {
            let publicKey = try MLDSA87.PublicKey(rawRepresentation: katTest.pk)
            let privateKey = try MLDSA87.PrivateKey(seedRepresentation: katTest.seed, publicKey: publicKey)
            let publicKeyHash = Data(SHA3_256.hash(data: privateKey.publicKey.rawRepresentation))

            XCTAssert(privateKey.seedRepresentation == katTest.seed)
            XCTAssert(privateKey.integrityCheckedRepresentation == katTest.seed + publicKeyHash)
            XCTAssert(privateKey.publicKey.rawRepresentation == katTest.pk)

            // Try initializing keys with incorrect integrity checks
            let randomPrivateKey = try MLDSA87.PrivateKey()
            let randomPublicKeyHash = Data(SHA3_256.hash(data: randomPrivateKey.publicKey.rawRepresentation))
            XCTAssertThrowsError(try MLDSA87.PrivateKey(seedRepresentation: privateKey.seedRepresentation, publicKey: randomPrivateKey.publicKey), error: CryptoKitError.unwrapFailure)
            XCTAssertThrowsError(try MLDSA87.PrivateKey(seedRepresentation: randomPrivateKey.seedRepresentation, publicKey: publicKey), error: CryptoKitError.unwrapFailure)
            XCTAssertThrowsError(try MLDSA87.PrivateKey(integrityCheckedRepresentation: privateKey.seedRepresentation + randomPublicKeyHash), error: CryptoKitError.unwrapFailure)
            XCTAssertThrowsError(try MLDSA87.PrivateKey(integrityCheckedRepresentation: randomPrivateKey.seedRepresentation + publicKeyHash), error: CryptoKitError.unwrapFailure)
        }
    }
}

// Struct to parse KAT file
struct MLDSAKeyGenKATHex: Codable {
    var seed: String
    var pk: String
    var sk: String
}

// Represent KAT with Data
struct MLDSAKeyGenKAT {
    var seed: Data
    var pk: Data
    var sk: Data
    init(_ hexRep: MLDSAKeyGenKATHex) throws {
        seed = try Data(hexString: hexRep.seed)
        pk = try Data(hexString: hexRep.pk)
        sk = try Data(hexString: hexRep.sk)
    }
}

#endif // CRYPTO_IN_SWIFTPM
