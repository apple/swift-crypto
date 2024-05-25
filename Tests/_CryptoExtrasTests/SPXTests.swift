//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
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
@testable import Crypto
import _CryptoExtras

final class SPXTests: XCTestCase {
    func testSPXSigning() throws {
        testSPXSigning(SPX.PrivateKey())
        // The seed provided here is 64 bytes long, but the SPX implementation only uses the first 48 bytes.
        let seed: [UInt8] = (0..<64).map { _ in UInt8.random(in: 0...255) }
        testSPXSigning(try SPX.PrivateKey(from: seed))
    }

    private func testSPXSigning(_ key: SPX.PrivateKey) {
        let test = Data("Hello, World!".utf8)

        XCTAssertTrue(
            key.publicKey.isValidSignature(
                key.signature(for: test),
                for: test
            )
        )
        
        // Test randomized signature
        XCTAssertTrue(
            key.publicKey.isValidSignature(
                key.signature(for: test, randomized: true),
                for: test
            )
        )
    }

    func testSignatureSerialization() {
        let data = Array("Hello, World!".utf8)
        let key = SPX.PrivateKey()
        let signature = key.signature(for: data)
        let roundTripped = SPX.Signature(rawRepresentation: signature.rawRepresentation)
        XCTAssertEqual(signature.rawRepresentation, roundTripped.rawRepresentation)
        XCTAssertTrue(key.publicKey.isValidSignature(roundTripped, for: data))
    }
    
    func testSPXKeyGeneration() throws {
        let seed: [UInt8] = Array(repeating: 0, count: (3 * 16))
        
        let expectedPublicKey: [UInt8] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x6b, 0xd7, 0xe8, 0xe1, 0x98,
            0xea, 0xf6, 0x2d, 0x57, 0x2f, 0x13, 0xfc, 0x79, 0xf2, 0x6f
        ]
        
        let expectedSecretKey: [UInt8] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xbe, 0x6b, 0xd7, 0xe8, 0xe1, 0x98, 0xea,
            0xf6, 0x2d, 0x57, 0x2f, 0x13, 0xfc, 0x79, 0xf2, 0x6f
        ]
        
        let key = try SPX.PrivateKey(from: seed)
        XCTAssertEqual(key.publicKey.bytes, expectedPublicKey)
        XCTAssertEqual(key.bytes, expectedSecretKey)
    }
    
    func testSPXKeyGeneration2() throws {
        let seed: [UInt8] = [
            0x3f, 0x00, 0xff, 0x1c, 0x9c, 0x5e, 0xaa, 0xfe, 0x09, 0xc3, 0x08, 0x0d,
            0xac, 0xc1, 0x83, 0x2b, 0x35, 0x8a, 0x40, 0xd5, 0xf3, 0x8c, 0xcb, 0x97,
            0xe3, 0xa6, 0xc1, 0xb3, 0xb7, 0x5f, 0x42, 0xab, 0x17, 0x34, 0xe6, 0x41,
            0x89, 0xe1, 0x57, 0x93, 0x12, 0x74, 0xdb, 0xbd, 0xb4, 0x28, 0xd0, 0xfb
        ]
        
        let expectedPublicKey: [UInt8] = [
            0x17, 0x34, 0xe6, 0x41, 0x89, 0xe1, 0x57, 0x93, 0x12, 0x74, 0xdb,
            0xbd, 0xb4, 0x28, 0xd0, 0xfb, 0x59, 0xc8, 0x64, 0xd2, 0x52, 0x96,
            0xa9, 0x22, 0xdc, 0x61, 0xb8, 0xc1, 0x92, 0x15, 0xac, 0x74
        ]
        
        let expectedSecretKey: [UInt8] = [
            0x3f, 0x00, 0xff, 0x1c, 0x9c, 0x5e, 0xaa, 0xfe, 0x09, 0xc3, 0x08,
            0x0d, 0xac, 0xc1, 0x83, 0x2b, 0x35, 0x8a, 0x40, 0xd5, 0xf3, 0x8c,
            0xcb, 0x97, 0xe3, 0xa6, 0xc1, 0xb3, 0xb7, 0x5f, 0x42, 0xab, 0x17,
            0x34, 0xe6, 0x41, 0x89, 0xe1, 0x57, 0x93, 0x12, 0x74, 0xdb, 0xbd,
            0xb4, 0x28, 0xd0, 0xfb, 0x59, 0xc8, 0x64, 0xd2, 0x52, 0x96, 0xa9,
            0x22, 0xdc, 0x61, 0xb8, 0xc1, 0x92, 0x15, 0xac, 0x74
        ]
        
        let key = try SPX.PrivateKey(from: seed)
        XCTAssertEqual(key.publicKey.bytes, expectedPublicKey)
        XCTAssertEqual(key.bytes, expectedSecretKey)
    }
    
    func testSPXSigningFile() throws {
        try spxTest(jsonName: "spx_tests") { testVector in
            var message = try Data(hexString: testVector.msg)
            let publicKey = try SPX.PublicKey(derRepresentation: Data(hexString: testVector.pk))
            let signature = try SPX.Signature(rawRepresentation: Data(hexString: testVector.sm))
            XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
            message[0] ^= 1
            XCTAssertFalse(publicKey.isValidSignature(signature, for: message))
        }
    }
    
    func testSPXSigningDeterministicFile() throws {
        try spxTest(jsonName: "spx_tests_deterministic") { testVector in
            let message = try Data(hexString: testVector.msg)
            let secretKey = try SPX.PrivateKey(derRepresentation: Data(hexString: testVector.sk))
            let expectedSignature = try SPX.Signature(rawRepresentation: Data(hexString: testVector.sm).prefix(7856))
            let signature = secretKey.signature(for: message)
            XCTAssertEqual(signature.rawRepresentation, expectedSignature.rawRepresentation)
        }
    }
}

struct SPXTestVector: Decodable {
    let count: Int
    let seed: String
    let mlen: Int
    let msg: String
    let pk: String
    let sk: String
    let smlen: Int
    let sm: String
}

struct SPXTestVectorFile: Decodable {
    let testVectors: [SPXTestVector]
}

func spxTest(jsonName: String, file: StaticString = #file, line: UInt = #line, testFunction: (SPXTestVector) throws -> Void) throws {
    let testsDirectory: String = URL(fileURLWithPath: "\(#file)").pathComponents.dropLast(2).joined(separator: "/")
    let fileURL: URL? = URL(fileURLWithPath: "\(testsDirectory)/_CryptoExtrasVectors/\(jsonName).json")

    let data = try Data(contentsOf: fileURL!)

    let decoder = JSONDecoder()
    let testFile = try decoder.decode(SPXTestVectorFile.self, from: data)

    for vector in testFile.testVectors {
        try testFunction(vector)
    }
}
