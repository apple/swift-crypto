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

final class MLDSATests: XCTestCase {
    func testMLDSASigning() throws {
        try testMLDSASigning(MLDSA.PrivateKey())
        let seed: [UInt8] = (0..<32).map { _ in UInt8.random(in: 0...255) }
        try testMLDSASigning(MLDSA.PrivateKey(seed: seed))
    }

    private func testMLDSASigning(_ key: MLDSA.PrivateKey) throws {
        let test = "Hello, world!".data(using: .utf8)!
        try XCTAssertTrue(
            key.publicKey.isValidSignature(
                key.signature(for: test),
                for: test
            )
        )
        
        let context = "ctx".data(using: .utf8)!
        try XCTAssertTrue(
            key.publicKey.isValidSignature(
                key.signature(for: test, context: context),
                for: test,
                context: context
            )
        )
    }

    func testSignatureSerialization() throws {
        let data = Array("Hello, World!".utf8)
        let key: MLDSA.PrivateKey = try MLDSA.PrivateKey()
        let signature = try key.signature(for: data)
        let roundTripped = MLDSA.Signature(rawRepresentation: signature.rawRepresentation)
        XCTAssertEqual(signature.rawRepresentation, roundTripped.rawRepresentation)
        XCTAssertTrue(key.publicKey.isValidSignature(roundTripped, for: data))
    }

    func testSeedRoundTripping() throws {
        let key = try MLDSA.PrivateKey()
        let seed = key.seed
        let roundTripped = try MLDSA.PrivateKey(seed: seed)
        XCTAssertEqual(seed, roundTripped.seed)
        XCTAssertEqual(key.publicKey.rawRepresentation, roundTripped.publicKey.rawRepresentation)
    }

    // This test is very slow, so it is disabled by default.
    func _testBitFlips() throws {
        let message = "Hello, world!".data(using: .utf8)!
        let key = try MLDSA.PrivateKey()
        let publicKey = key.publicKey
        let signature = try key.signature(for: message)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
        
        var encodedSignature = signature.rawRepresentation
        for i in 0..<encodedSignature.count {
            for j in 0..<8 {
                encodedSignature[i] ^= 1 << j
                let modifiedSignature = MLDSA.Signature(rawRepresentation: encodedSignature)
                XCTAssertFalse(
                    publicKey.isValidSignature(modifiedSignature, for: message),
                    "Bit flip in signature at byte \(i) bit \(j) didn't cause a verification failure"
                )
                encodedSignature[i] ^= 1 << j
            }
        }
    }

    func testSignatureIsRandomized() throws {
        let message = "Hello, world!".data(using: .utf8)!
        
        let seed: [UInt8] = (0..<32).map { _ in UInt8.random(in: 0...255) }
        let key = try MLDSA.PrivateKey(seed: seed)
        let publicKey = key.publicKey
        
        let signature1 = try key.signature(for: message)
        let signature2 = try key.signature(for: message)
        
        XCTAssertNotEqual(signature1.rawRepresentation, signature2.rawRepresentation)
        
        // Even though the signatures are different, they both verify.
        XCTAssertTrue(publicKey.isValidSignature(signature1, for: message))
        XCTAssertTrue(publicKey.isValidSignature(signature2, for: message))
    }

    func testInvalidPublicKeyEncodingLength() throws {
        // Encode a public key with a trailing 0 at the end.
        var encodedPublicKey = [UInt8](repeating: 0, count: MLDSA.PublicKey.bytesCount + 1)
        let seed: [UInt8] = (0..<32).map { _ in UInt8.random(in: 0...255) }
        let key = try MLDSA.PrivateKey(seed: seed)
        let publicKey = key.publicKey
        encodedPublicKey.replaceSubrange(0..<MLDSA.PublicKey.bytesCount, with: publicKey.rawRepresentation)
        
        // Public key is 1 byte too short.
        let shortPublicKey = Array(encodedPublicKey.prefix(MLDSA.PublicKey.bytesCount - 1))
        XCTAssertThrowsError(try MLDSA.PublicKey(rawRepresentation: shortPublicKey))
        
        // Public key has the correct length.
        let correctLengthPublicKey = Array(encodedPublicKey.prefix(MLDSA.PublicKey.bytesCount))
        XCTAssertNoThrow(try MLDSA.PublicKey(rawRepresentation: correctLengthPublicKey))
        
        // Public key is 1 byte too long.
        XCTAssertThrowsError(try MLDSA.PublicKey(rawRepresentation: encodedPublicKey))
    }

    func testMLDSANISTKeyGenFile() throws {
        try nistTest(jsonName: "mldsa_nist_keygen_tests") { (testVector: NISTKeyGenTestVector) in
            let seed = try Data(hexString: testVector.seed)
            let publicKey = try MLDSA.PublicKey(rawRepresentation: Data(hexString: testVector.pub))
            
            let expectedkey = try MLDSA.PrivateKey(seed: seed).publicKey
            XCTAssertEqual(publicKey.rawRepresentation, expectedkey.rawRepresentation)
        }
    }

    private struct NISTKeyGenTestVector: Decodable {
        let seed: String
        let pub: String
        let priv: String
    }

    private struct NISTTestFile<Vector: Decodable>: Decodable {
        let testVectors: [Vector]
    }

    private func nistTest<Vector: Decodable>(
        jsonName: String, file: StaticString = #file, line: UInt = #line, testFunction: (Vector) throws -> Void
    ) throws {
        let testsDirectory: String = URL(fileURLWithPath: "\(#file)").pathComponents.dropLast(2).joined(separator: "/")
        let fileURL: URL? = URL(fileURLWithPath: "\(testsDirectory)/_CryptoExtrasVectors/\(jsonName).json")
        let data = try Data(contentsOf: fileURL!)
        let testFile = try JSONDecoder().decode(NISTTestFile<Vector>.self, from: data)
        for vector in testFile.testVectors {
            try testFunction(vector)
        }
    }

    func testMLDSAWycheproofVerifyFile() throws {
        try wycheproofTest(jsonName: "mldsa_65_standard_verify_test") { (testGroup: WycheproofTestGroup) in
            let publicKey: MLDSA.PublicKey
            do {
                publicKey = try MLDSA.PublicKey(rawRepresentation: Data(hexString: testGroup.publicKey))
            } catch {
                if testGroup.tests.contains(where: { $0.flags.contains(.incorrectPublicKeyLength) }) { return }
                throw error
            }
            for test in testGroup.tests {
                let message = try Data(hexString: test.msg)
                let signature = try MLDSA.Signature(rawRepresentation: Data(hexString: test.sig))
                let context = try test.ctx.map { try Data(hexString: $0) }
                
                switch test.result {
                case .valid:
                    XCTAssertTrue(publicKey.isValidSignature(signature, for: message, context: context))
                case .invalid:
                    XCTAssertFalse(publicKey.isValidSignature(signature, for: message, context: context))
                }
            }
        }
    }

    struct WycheproofTestGroup: Codable {
        let publicKey: String
        let tests: [WycheproofTest]

        struct WycheproofTest: Codable {
            let msg, sig: String
            let result: Result
            let flags: [Flag]
            let ctx: String?

            enum Flag: String, Codable {
                case boundaryCondition = "BoundaryCondition"
                case incorrectPublicKeyLength = "IncorrectPublicKeyLength"
                case incorrectSignatureLength = "IncorrectSignatureLength"
                case invalidContext = "InvalidContext"
                case invalidHintsEncoding = "InvalidHintsEncoding"
                case invalidPrivateKey = "InvalidPrivateKey"
                case manySteps = "ManySteps"
                case modifiedSignature = "ModifiedSignature"
                case validSignature = "ValidSignature"
                case zeroPublicKey = "ZeroPublicKey"
            }

            enum Result: String, Codable {
                case invalid
                case valid
            }
        }
    }
}
