//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
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

// Test Vectors are coming from ANSI X9.63-2001.
class X963KDFTests: XCTestCase {
    struct TestVector: Codable {
        var inputSecret: [UInt8]
        var sharedInfo: [UInt8]
        var outputKeyMaterial: [UInt8]

        enum CodingKeys: String, CodingKey {
            case inputSecret = "Z"
            case sharedInfo = "SharedInfo"
            case outputKeyMaterial = "key_data"
        }
    }

    func testVector<H: HashFunction>(_ vector: TestVector, hash: H.Type) throws {
        // We test the RFC test vector here. We do it with as much variety as possible: there is one DataProtocol
        // input, so we generate 2 keys.
        let ss = SharedSecret(ss: SecureBytes(bytes: vector.inputSecret))
        let (contiguousSharedInfo, discontiguousSharedInfo) = vector.sharedInfo.asDataProtocols()

        let firstKey = ss.x963DerivedSymmetricKey(using: H.self, sharedInfo: contiguousSharedInfo, outputByteCount: vector.outputKeyMaterial.count)
        let secondKey = ss.x963DerivedSymmetricKey(using: H.self, sharedInfo: discontiguousSharedInfo, outputByteCount: vector.outputKeyMaterial.count)

        let expectedKey = SymmetricKey(data: vector.outputKeyMaterial)
        XCTAssertEqual(firstKey, expectedKey)
        XCTAssertEqual(secondKey, expectedKey)
    }

    func testVectorsSHA1() throws {
        // The RFC vector decoder works here too.
        var decoder = try orFail { try RFCVectorDecoder(bundleType: self, fileName: "ansx963_2001_sha1") }
        let vectors = try orFail { try decoder.decode([TestVector].self) }

        for vector in vectors {
            try orFail { try self.testVector(vector, hash: Insecure.SHA1.self) }
        }
    }

    func testRfcTestVectorsSHA256() throws {
        // The RFC vector decoder works here too.
        var decoder = try orFail { try RFCVectorDecoder(bundleType: self, fileName: "ansx963_2001_sha256") }
        let vectors = try orFail { try decoder.decode([TestVector].self) }

        for vector in vectors {
            try orFail { try self.testVector(vector, hash: SHA256.self) }
        }
    }

    func testRfcTestVectorsSHA384() throws {
        // The RFC vector decoder works here too.
        var decoder = try orFail { try RFCVectorDecoder(bundleType: self, fileName: "ansx963_2001_sha384") }
        let vectors = try orFail { try decoder.decode([TestVector].self) }

        for vector in vectors {
            try orFail { try self.testVector(vector, hash: SHA384.self) }
        }
    }

    func testRfcTestVectorsSHA512() throws {
        // The RFC vector decoder works here too.
        var decoder = try orFail { try RFCVectorDecoder(bundleType: self, fileName: "ansx963_2001_sha512") }
        let vectors = try orFail { try decoder.decode([TestVector].self) }

        for vector in vectors {
            try orFail { try self.testVector(vector, hash: SHA512.self) }
        }
    }
}

#endif // (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM
