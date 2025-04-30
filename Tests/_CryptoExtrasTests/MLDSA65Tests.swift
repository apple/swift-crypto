//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import XCTest

@testable import _CryptoExtras

final class MLDSA65Tests: XCTestCase {
    func testMLDSA65Signing() throws {
        try testMLDSA65Signing(MLDSA65.PrivateKey())
        let seed: [UInt8] = (0..<32).map { _ in UInt8.random(in: 0...255) }
        try testMLDSA65Signing(MLDSA65.PrivateKey(seedRepresentation: seed))
    }

    private func testMLDSA65Signing(_ key: MLDSA65.PrivateKey) throws {
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

    func testSeedRoundTripping() throws {
        let key = try MLDSA65.PrivateKey()
        let seed = key.seedRepresentation
        let roundTripped = try MLDSA65.PrivateKey(seedRepresentation: seed)
        XCTAssertEqual(seed, roundTripped.seedRepresentation)
        XCTAssertEqual(key.publicKey.rawRepresentation, roundTripped.publicKey.rawRepresentation)
    }

    func testSignatureIsRandomized() throws {
        let message = "Hello, world!".data(using: .utf8)!

        let seed: [UInt8] = (0..<32).map { _ in UInt8.random(in: 0...255) }
        let key = try MLDSA65.PrivateKey(seedRepresentation: seed)
        let publicKey = key.publicKey

        let signature1 = try key.signature(for: message)
        let signature2 = try key.signature(for: message)

        XCTAssertNotEqual(signature1, signature2)

        // Even though the signatures are different, they both verify.
        XCTAssertTrue(publicKey.isValidSignature(signature1, for: message))
        XCTAssertTrue(publicKey.isValidSignature(signature2, for: message))
    }

    func testInvalidPublicKeyEncodingLength() throws {
        // Encode a public key with a trailing 0 at the end.
        var encodedPublicKey = [UInt8](repeating: 0, count: MLDSA65.PublicKey.byteCount + 1)
        let seed: [UInt8] = (0..<32).map { _ in UInt8.random(in: 0...255) }
        let key = try MLDSA65.PrivateKey(seedRepresentation: seed)
        let publicKey = key.publicKey
        encodedPublicKey.replaceSubrange(0..<MLDSA65.PublicKey.byteCount, with: publicKey.rawRepresentation)

        // Public key is 1 byte too short.
        let shortPublicKey = Array(encodedPublicKey.prefix(MLDSA65.PublicKey.byteCount - 1))
        XCTAssertThrowsError(try MLDSA65.PublicKey(rawRepresentation: shortPublicKey))

        // Public key has the correct length.
        let correctLengthPublicKey = Array(encodedPublicKey.prefix(MLDSA65.PublicKey.byteCount))
        XCTAssertNoThrow(try MLDSA65.PublicKey(rawRepresentation: correctLengthPublicKey))

        // Public key is 1 byte too long.
        XCTAssertThrowsError(try MLDSA65.PublicKey(rawRepresentation: encodedPublicKey))
    }

    func testMLDSA65NISTKeyGenFile() throws {
        try nistTest(jsonName: "mldsa_65_nist_keygen_tests") { (testVector: NISTKeyGenTestVector) in
            let seed = try Data(hexString: testVector.seed)
            let publicKey = try MLDSA65.PublicKey(rawRepresentation: Data(hexString: testVector.pub))

            let expectedkey = try MLDSA65.PrivateKey(seedRepresentation: seed).publicKey
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
        jsonName: String,
        file: StaticString = #file,
        line: UInt = #line,
        testFunction: (Vector) throws -> Void
    ) throws {
        var fileURL = URL(fileURLWithPath: "\(#file)")
        for _ in 0..<2 {
            fileURL.deleteLastPathComponent()
        }
        #if compiler(>=6.0)
        if #available(macOS 13, iOS 16, watchOS 9, tvOS 16, visionOS 1, macCatalyst 16, *) {
            fileURL.append(path: "_CryptoExtrasVectors", directoryHint: .isDirectory)
            fileURL.append(path: "\(jsonName).json", directoryHint: .notDirectory)
        } else {
            fileURL = fileURL.appendingPathComponent("_CryptoExtrasVectors", isDirectory: true)
            fileURL = fileURL.appendingPathComponent("\(jsonName).json", isDirectory: false)
        }
        #else
        fileURL = fileURL.appendingPathComponent("_CryptoExtrasVectors", isDirectory: true)
        fileURL = fileURL.appendingPathComponent("\(jsonName).json", isDirectory: false)
        #endif

        let data = try Data(contentsOf: fileURL)

        let testFile = try JSONDecoder().decode(NISTTestFile<Vector>.self, from: data)

        for vector in testFile.testVectors {
            try testFunction(vector)
        }
    }

    func testMLDSA65WycheproofVerifyFile() throws {
        try wycheproofTest(jsonName: "mldsa_65_standard_verify_test") { (testGroup: WycheproofTestGroup) in
            let publicKey: MLDSA65.PublicKey
            do {
                publicKey = try MLDSA65.PublicKey(rawRepresentation: Data(hexString: testGroup.publicKey))
            } catch {
                if testGroup.tests.contains(where: { $0.flags.contains(.incorrectPublicKeyLength) }) { return }
                throw error
            }
            for test in testGroup.tests {
                let message = try Data(hexString: test.msg)
                let signature = try Data(hexString: test.sig)
                let context = try test.ctx.map { try Data(hexString: $0) }

                switch test.result {
                case .valid:
                    if let context {
                        XCTAssertTrue(publicKey.isValidSignature(signature, for: message, context: context))
                    } else {
                        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
                    }
                case .invalid:
                    if let context {
                        XCTAssertFalse(publicKey.isValidSignature(signature, for: message, context: context))
                    } else {
                        XCTAssertFalse(publicKey.isValidSignature(signature, for: message))
                    }
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
