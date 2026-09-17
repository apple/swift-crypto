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
#if canImport(CryptoKit)
// Skip tests that require @testable imports of CryptoKit.
#else
@testable import Crypto

final class MLKEMTests: XCTestCase {
    /// Decapsulates with the regular private key and also with a one-time private key built from the
    /// same key material, asserting that both paths recover the same shared secret. Returns the shared
    /// secret so callers can run their own assertions (e.g. against a known-answer value), guaranteeing
    /// the one-time and regular decapsulation functions are tested identically everywhere.
    private func decapsulate(
        with privateKey: MLKEM768.PrivateKey,
        _ encapsulated: Data,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws -> SymmetricKey {
        let sharedSecret = try privateKey.decapsulate(encapsulated)
        let oneTimeSharedSecret = try MLKEM768.OneTimePrivateKey(reusingForTestingOnly: privateKey).decapsulate(encapsulated)
        XCTAssertEqual(sharedSecret, oneTimeSharedSecret, "one-time decapsulation diverged from regular decapsulation", file: file, line: line)
        return sharedSecret
    }

    private func decapsulate(
        with privateKey: MLKEM1024.PrivateKey,
        _ encapsulated: Data,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws -> SymmetricKey {
        let sharedSecret = try privateKey.decapsulate(encapsulated)
        let oneTimeSharedSecret = try MLKEM1024.OneTimePrivateKey(reusingForTestingOnly: privateKey).decapsulate(encapsulated)
        XCTAssertEqual(sharedSecret, oneTimeSharedSecret, "one-time decapsulation diverged from regular decapsulation", file: file, line: line)
        return sharedSecret
    }

    func testMLKEM768() throws {
        let privateKey = try MLKEM768.PrivateKey.generate()
        let publicKey = privateKey.publicKey

        // Test Public Key Serialization
        try XCTAssert(publicKey.rawRepresentation == MLKEM768.PublicKey(rawRepresentation: publicKey.rawRepresentation).rawRepresentation)

        // Test Private Key serialization
        try XCTAssert(privateKey.seedRepresentation == MLKEM768.PrivateKey(seedRepresentation: privateKey.seedRepresentation, publicKey: publicKey).seedRepresentation)
        try XCTAssert(privateKey.integrityCheckedRepresentation == MLKEM768.PrivateKey(integrityCheckedRepresentation: privateKey.integrityCheckedRepresentation).integrityCheckedRepresentation)

        let er = try publicKey.encapsulate()
        let ss = try decapsulate(with: privateKey, er.encapsulated)

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
        let ss = try decapsulate(with: privateKey, er.encapsulated)

        XCTAssert(er.sharedSecret == ss)
    }

    // Test that the private key API function throws on an invalid seed
    func testPrivateKeyInitThrowsOnInvalidSeedLength768() {
        XCTAssertThrowsError(try MLKEM768.PrivateKey(seedRepresentation: Data(count: 1), publicKey: nil))
    }

    func testPrivateKeyInitThrowsOnInvalidSeedLength1024() {
        XCTAssertThrowsError(try MLKEM1024.PrivateKey(seedRepresentation: Data(count: 1), publicKey: nil))
    }

    func processKATFile(filename: String) throws -> [MLKEMKAT] {
        let bundle = Bundle.module
        let fileURL = bundle.url(forResource: filename, withExtension: "json")
        let json = try Data(contentsOf: fileURL!)
        let stringInput = String(data: json, encoding: .ascii)!
        let tests = try JSONDecoder().decode([MLKEMKATHex].self, from: stringInput.data(using: .ascii)!)
        return try tests.map { try MLKEMKAT($0) }
    }

    func test768KAT() throws {
        // No support for encapsulateWithSeed in BoringSSL.
        throw XCTSkip()
    }

    func test1024KAT() throws {
        // No support for encapsulateWithSeed in BoringSSL.
        throw XCTSkip()
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

#endif // canImport(CryptoKit)
