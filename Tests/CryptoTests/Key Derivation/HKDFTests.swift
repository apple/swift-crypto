//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import XCTest

#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// Skip tests that require @testable imports of CryptoKit.
#else
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@testable import CryptoKit
#else
@testable import Crypto
#endif

// Test Vectors are coming from https://tools.ietf.org/html/rfc5869
class HKDFTests: XCTestCase {
    struct RFCTestVector: Codable {
        var hash: String
        var inputSecret: [UInt8]
        var salt: [UInt8]
        var sharedInfo: [UInt8]
        var outputLength: Int
        var outputKeyMaterial: [UInt8]

        enum CodingKeys: String, CodingKey {
            case hash = "Hash"
            case inputSecret = "IKM"
            case salt
            case sharedInfo = "info"
            case outputLength = "L"
            case outputKeyMaterial = "OKM"
        }
    }

    func testRFCVector<H: HashFunction>(_ vector: RFCTestVector, hash: H.Type) throws {
        // We test the RFC test vector here. We do it with as much variety as possible: there are two DataProtocol
        // inputs, so we generate 4 keys.
        let ss = SharedSecret(ss: SecureBytes(bytes: vector.inputSecret))
        let (contiguousSalt, discontiguousSalt) = vector.salt.asDataProtocols()
        let (contiguousSharedInfo, discontiguousSharedInfo) = vector.sharedInfo.asDataProtocols()

        let firstKey = ss.hkdfDerivedSymmetricKey(using: H.self, salt: contiguousSalt,
                                                  sharedInfo: contiguousSharedInfo, outputByteCount: vector.outputLength)
        let secondKey = ss.hkdfDerivedSymmetricKey(using: H.self, salt: contiguousSalt,
                                                   sharedInfo: discontiguousSharedInfo, outputByteCount: vector.outputLength)
        let thirdKey = ss.hkdfDerivedSymmetricKey(using: H.self, salt: discontiguousSalt,
                                                  sharedInfo: contiguousSharedInfo, outputByteCount: vector.outputLength)
        let fourthKey = ss.hkdfDerivedSymmetricKey(using: H.self, salt: discontiguousSalt,
                                                   sharedInfo: discontiguousSharedInfo, outputByteCount: vector.outputLength)

        let expectedKey = SymmetricKey(data: vector.outputKeyMaterial)
        XCTAssertEqual(firstKey, expectedKey)
        XCTAssertEqual(secondKey, expectedKey)
        XCTAssertEqual(thirdKey, expectedKey)
        XCTAssertEqual(fourthKey, expectedKey)
    }
    
    func testRfcTestVectorsSHA1() throws {
        var decoder = try orFail { try RFCVectorDecoder(bundleType: self, fileName: "rfc-5869-HKDF-SHA1") }
        let vectors = try orFail { try decoder.decode([RFCTestVector].self) }

        for vector in vectors {
            precondition(vector.hash == "SHA-1")
            try orFail { try self.testRFCVector(vector, hash: Insecure.SHA1.self) }
        }
    }

    func testRfcTestVectorsSHA256() throws {
        var decoder = try orFail { try RFCVectorDecoder(bundleType: self, fileName: "rfc-5869-HKDF-SHA256") }
        let vectors = try orFail { try decoder.decode([RFCTestVector].self) }

        for vector in vectors {
            precondition(vector.hash == "SHA-256")
            try orFail { try self.testRFCVector(vector, hash: SHA256.self) }
        }
    }
}

#endif // (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM
