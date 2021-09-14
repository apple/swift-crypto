//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import XCTest

@testable import Crypto

// Test Vectors are coming from https://tools.ietf.org/html/rfc6070
class PBKDF2Tests: XCTestCase {
    struct RFCTestVector: Codable {
        var hash: String
        var inputSecret: [UInt8]
        var salt: [UInt8]
        var rounds: Int
        var outputLength: Int
        var derivedKey: [UInt8]
        
        enum CodingKeys: String, CodingKey {
            case hash = "Hash"
            case inputSecret = "P"
            case salt = "S"
            case rounds = "c"
            case outputLength = "dkLen"
            case derivedKey = "DK"
        }
    }
        
    func oneshotTesting<H: HashFunction>(_ vector: RFCTestVector, hash: H.Type) throws {
        let (contiguousInput, discontiguousInput) = vector.inputSecret.asDataProtocols()
        let (contiguousSalt, discontiguousSalt) = vector.salt.asDataProtocols()
        
        let DK1 = try PBKDF2<H>.deriveKey(from: contiguousInput, salt: contiguousSalt,
                                      outputByteCount: vector.outputLength,
                                      rounds: vector.rounds)
        
        let DK2 = try PBKDF2<H>.deriveKey(from: discontiguousInput, salt: contiguousSalt,
                                      outputByteCount: vector.outputLength,
                                      rounds: vector.rounds)
        
        let DK3 = try PBKDF2<H>.deriveKey(from: contiguousInput, salt: discontiguousSalt,
                                      outputByteCount: vector.outputLength,
                                      rounds: vector.rounds)
        
        let DK4 = try PBKDF2<H>.deriveKey(from: discontiguousInput, salt: discontiguousSalt,
                                      outputByteCount: vector.outputLength,
                                      rounds: vector.rounds)
                
        let expectedDK = SymmetricKey(data: vector.derivedKey)
        XCTAssertEqual(DK1, expectedDK)
        XCTAssertEqual(DK2, expectedDK)
        XCTAssertEqual(DK3, expectedDK)
        XCTAssertEqual(DK4, expectedDK)
    }
        
    func testRFCVector<H: HashFunction>(_ vector: RFCTestVector, hash: H.Type) throws {
        try oneshotTesting(vector, hash: hash)
    }
    
    func testRfcTestVectorsSHA1() throws {
        var decoder = try orFail { try RFCVectorDecoder(bundleType: self, fileName: "rfc-6070-PBKDF2-SHA1") }
        let vectors = try orFail { try decoder.decode([RFCTestVector].self) }
        
        for vector in vectors {
            precondition(vector.hash == "SHA-1")
            try orFail { try self.testRFCVector(vector, hash: Insecure.SHA1.self) }
        }
    }
}
