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

import XCTest
@testable import _CryptoExtras

final class SLHDSATests: XCTestCase {
    func testSLHDSASigning() throws {
        let key = SLHDSA.PrivateKey()
        let test = Data("Hello, World!".utf8)

        try XCTAssertTrue(
            key.publicKey.isValidSignature(
                key.signature(for: test),
                for: test
            )
        )
    }

    func testSignatureSerialization() throws {
        let data = Array("Hello, World!".utf8)
        let key = SLHDSA.PrivateKey()
        let signature = try key.signature(for: data)
        let roundTripped = SLHDSA.Signature(rawRepresentation: signature.rawRepresentation)
        XCTAssertEqual(signature.rawRepresentation, roundTripped.rawRepresentation)
        XCTAssertTrue(key.publicKey.isValidSignature(roundTripped, for: data))
    }

    func testSLHDSASigGenFile() throws {
        try slhdsaTest(jsonName: "slhdsa_siggen") { (testVector: SLHDSASigGenTestVector) in
            let publicKey = try SLHDSA.PrivateKey(derRepresentation: Data(hexString: testVector.priv)).publicKey
            let signature = try SLHDSA.Signature(rawRepresentation: Data(hexString: testVector.sig))
            let message = try Data(hexString: testVector.msg)

            XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
        }
    }
    
    func testSLHDSASigVerFile() throws {
        try slhdsaTest(jsonName: "slhdsa_sigver") { (testVector: SLHDSASigVerTestVector) in
            let publicKey = try SLHDSA.PublicKey(derRepresentation: Data(hexString: testVector.pub))
            let signature = try SLHDSA.Signature(rawRepresentation: Data(hexString: testVector.sig))
            let message = try Data(hexString: testVector.msg)

            XCTAssertEqual(publicKey.derRepresentation.count, 32)
            XCTAssertEqual(publicKey.isValidSignature(signature, for: message), testVector.valid)
        }
    }

    private struct SLHDSASigGenTestVector: Decodable {
        let priv: String
        let entropy: String
        let msg: String
        let sig: String
    }

    private struct SLHDSASigVerTestVector: Decodable {
        let pub: String
        let msg: String
        let sig: String
        let valid: Bool
    }

    private struct SLHDSATestFile<Vector: Decodable>: Decodable {
        let testVectors: [Vector]
    }

    private func slhdsaTest<Vector: Decodable>(
        jsonName: String, file: StaticString = #file, line: UInt = #line, testFunction: (Vector) throws -> Void
    ) throws {
        let testsDirectory: String = URL(fileURLWithPath: "\(#file)").pathComponents.dropLast(2).joined(separator: "/")
        let fileURL: URL? = URL(fileURLWithPath: "\(testsDirectory)/_CryptoExtrasVectors/\(jsonName).json")
        let data = try Data(contentsOf: fileURL!)
        let testFile = try JSONDecoder().decode(SLHDSATestFile<Vector>.self, from: data)
        for vector in testFile.testVectors {
            try testFunction(vector)
        }
    }
}
