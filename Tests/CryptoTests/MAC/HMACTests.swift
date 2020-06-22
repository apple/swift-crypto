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

// Test Vectors are coming from https://tools.ietf.org/html/rfc4231
class HMACTests: XCTestCase {
    func testUsage() {
        let key = SymmetricKey(size: .bits256)

        let someData = "SomeData".data(using: .utf8)!

        let mac = HMAC<SHA256>.authenticationCode(for: someData, using: key)
        XCTAssert(HMAC.isValidAuthenticationCode(mac, authenticating: someData, using: key))
    }
    
    // Test Case 1
    func testCase1VectorForAlgorithm<H: HashFunction>(hashFunction: H.Type) throws -> String {
        switch H.self {
        case is SHA256.Type: return "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        case is SHA384.Type: return "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"
        case is SHA512.Type: return "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        default:
            XCTFail("Unhandled type: \(H.self)")
            throw TestError.unhandled
        }
    }
    
    // Test Case 2
    func testCase2VectorForAlgorithm<H: HashFunction>(hashFunction: H.Type) throws -> String {
        switch H.self {
        case is SHA256.Type: return "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        case is SHA384.Type: return "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"
        case is SHA512.Type: return "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        default:
            XCTFail("Unhandled type: \(H.self)")
            throw TestError.unhandled
        }
    }
    
    // Test Case 3
    func testCase3VectorForAlgorithm<H: HashFunction>(hashFunction: H.Type) throws -> String {
        switch H.self {
        case is SHA256.Type: return "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        case is SHA384.Type: return "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27"
        case is SHA512.Type: return "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
        default:
            XCTFail("Unhandled type: \(H.self)")
            throw TestError.unhandled
        }
    }
    
    // Test Case 4
    func testCase4VectorForAlgorithm<H: HashFunction>(hashFunction: H.Type) throws -> String {
        switch H.self {
        case is SHA256.Type: return "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
        case is SHA384.Type: return "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb"
        case is SHA512.Type: return "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"
        default:
            XCTFail("Unhandled type: \(H.self)")
            throw TestError.unhandled
        }
    }
    
    // Test Case 6
    func testCase6VectorForAlgorithm<H: HashFunction>(hashFunction: H.Type) throws -> String {
        switch H.self {
        case is SHA256.Type: return "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        case is SHA384.Type: return "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"
        case is SHA512.Type: return "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
        default:
            XCTFail("Unhandled type: \(H.self)")
            throw TestError.unhandled
        }
    }
    
    // Test Case 7
    func testCase7VectorForAlgorithm<H: HashFunction>(hashFunction: H.Type) throws -> String {
        switch H.self {
        case is SHA256.Type: return "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
        case is SHA384.Type: return "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e"
        case is SHA512.Type: return "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"
        default:
            XCTFail("Unhandled type: \(H.self)")
            throw TestError.unhandled
        }
    }
    
    func testHMAC<H: HashFunction>(key: SymmetricKey, data: Data, vectors: (H.Type) throws -> String, for: H.Type, file: StaticString = #file, line: UInt = #line) throws -> Bool {
        let code = try orFail(file: file, line: line) { try Data(hexString: vectors(H.self)) }
        return HMAC<H>.isValidAuthenticationCode(code, authenticating: data, using: key)
    }
    
    func testCase1() throws {
        let keyBytes = try orFail { try Array(hexString: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b") }
        let key = SymmetricKey(data: keyBytes)
        
        let data = "Hi There".data(using: .ascii)!
        
        XCTAssert(try testHMAC(key: key, data: data, vectors: testCase1VectorForAlgorithm, for: SHA256.self))
        XCTAssert(try testHMAC(key: key, data: data, vectors: testCase1VectorForAlgorithm, for: SHA384.self))
        XCTAssert(try testHMAC(key: key, data: data, vectors: testCase1VectorForAlgorithm, for: SHA512.self))
    }
    
    func testCase2() throws {
        let keyBytes = try orFail { try Array(hexString: "4a656665") }
        let key = SymmetricKey(data: keyBytes)
        
        let data = try orFail { try Data(hexString: "7768617420646f2079612077616e7420666f72206e6f7468696e673f") }
        
        XCTAssert(try testHMAC(key: key, data: data, vectors: testCase2VectorForAlgorithm, for: SHA256.self))
        XCTAssert(try testHMAC(key: key, data: data, vectors: testCase2VectorForAlgorithm, for: SHA384.self))
        XCTAssert(try testHMAC(key: key, data: data, vectors: testCase2VectorForAlgorithm, for: SHA512.self))
    }
    
    func testCase3() throws {
        let keyBytes = try orFail { try Array(hexString: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") }
        let key = SymmetricKey(data: keyBytes)
        
        let data = try orFail { try Data(hexString: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd") }
        
        XCTAssert(try testHMAC(key: key, data: data, vectors: testCase3VectorForAlgorithm, for: SHA256.self))
        XCTAssert(try testHMAC(key: key, data: data, vectors: testCase3VectorForAlgorithm, for: SHA384.self))
        XCTAssert(try testHMAC(key: key, data: data, vectors: testCase3VectorForAlgorithm, for: SHA512.self))
    }
    
    func testCase4() throws {
        let keyBytes = try orFail { try Array(hexString: "0102030405060708090a0b0c0d0e0f10111213141516171819") }
        let key = SymmetricKey(data: keyBytes)
        
        let data = try orFail { try Data(hexString: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd") }
        
        XCTAssert(try testHMAC(key: key, data: data, vectors: testCase4VectorForAlgorithm, for: SHA256.self))
        XCTAssert(try testHMAC(key: key, data: data, vectors: testCase4VectorForAlgorithm, for: SHA384.self))
        XCTAssert(try testHMAC(key: key, data: data, vectors: testCase4VectorForAlgorithm, for: SHA512.self))
    }
    
    func testCase6() throws {
        let keyBytes = try orFail { try Array(hexString: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") }
        let key = SymmetricKey(data: keyBytes)
        
        let data = try orFail { try Data(hexString: "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374") }
        
        XCTAssert(try testHMAC(key: key, data: data, vectors: testCase6VectorForAlgorithm, for: SHA256.self))
        XCTAssert(try testHMAC(key: key, data: data, vectors: testCase6VectorForAlgorithm, for: SHA384.self))
        XCTAssert(try testHMAC(key: key, data: data, vectors: testCase6VectorForAlgorithm, for: SHA512.self))
    }
    
    func testCase7() throws {
        let keyBytes = try orFail { try Array(hexString: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") }
        let key = SymmetricKey(data: keyBytes)
        
        let data = try orFail { try Data(hexString: "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e") }
        
        XCTAssert(try testHMAC(key: key, data: data, vectors: testCase7VectorForAlgorithm, for: SHA256.self))
        XCTAssert(try testHMAC(key: key, data: data, vectors: testCase7VectorForAlgorithm, for: SHA384.self))
        XCTAssert(try testHMAC(key: key, data: data, vectors: testCase7VectorForAlgorithm, for: SHA512.self))
    }

    func testDiscontiguousHMAC<H: HashFunction>(key: SymmetricKey, data: [UInt8], for: H.Type) {
        let (contiguousData, discontiguousData) = data.asDataProtocols()

        let authContiguous = HMAC<H>.authenticationCode(for: contiguousData, using: key)
        let authDiscontiguous = HMAC<H>.authenticationCode(for: discontiguousData, using: key)
        XCTAssertEqual(authContiguous, authDiscontiguous)
        XCTAssertEqual(authContiguous.byteCount, H.Digest.byteCount)
        XCTAssertEqual(authDiscontiguous.byteCount, H.Digest.byteCount)

        XCTAssertTrue(HMAC<H>.isValidAuthenticationCode(authContiguous, authenticating: contiguousData, using: key))
        XCTAssertTrue(HMAC<H>.isValidAuthenticationCode(authContiguous, authenticating: discontiguousData, using: key))
        XCTAssertTrue(HMAC<H>.isValidAuthenticationCode(authDiscontiguous, authenticating: contiguousData, using: key))
        XCTAssertTrue(HMAC<H>.isValidAuthenticationCode(authDiscontiguous, authenticating: discontiguousData, using: key))

        let unrelatedAuthenticationCode = HMAC<H>.authenticationCode(for: Array("hello, world!".utf8), using: key)
        XCTAssertFalse(HMAC<H>.isValidAuthenticationCode(unrelatedAuthenticationCode, authenticating: contiguousData, using: key))
        XCTAssertFalse(HMAC<H>.isValidAuthenticationCode(unrelatedAuthenticationCode, authenticating: discontiguousData, using: key))

        // The HashedAuthenticationCode itself also has a == implementation against DataProtocols, so we want to test that.
        let (contiguousGoodCode, discontiguousGoodCode) = Array(authContiguous).asDataProtocols()
        XCTAssertTrue(authContiguous == contiguousGoodCode)
        XCTAssertTrue(authContiguous == discontiguousGoodCode)
        XCTAssertFalse(unrelatedAuthenticationCode == contiguousGoodCode)
        XCTAssertFalse(unrelatedAuthenticationCode == discontiguousGoodCode)
    }

    func testDiscontiguousSHA256() {
        testDiscontiguousHMAC(key: SymmetricKey(size: .bits256), data: Array("some data".utf8), for: SHA256.self)
    }

    func testDiscontiguousSHA384() {
        testDiscontiguousHMAC(key: SymmetricKey(size: .bits256), data: Array("some data".utf8), for: SHA384.self)
    }

    func testDiscontiguousSHA512() {
        testDiscontiguousHMAC(key: SymmetricKey(size: .bits256), data: Array("some data".utf8), for: SHA512.self)
    }

    func testHMACViaPointer() throws {
        let key = SymmetricKey(size: .bits256)
        let someData = "SomeData".data(using: .utf8)!

        let mac = HMAC<SHA256>.authenticationCode(for: someData, using: key)
        someData.withUnsafeBytes { bytesPointer in
            XCTAssert(HMAC.isValidAuthenticationCode(mac, authenticating: bytesPointer, using: key))
        }
    }

    func testMACEqualityAgainstEmptyDispatchData() throws {
        let key = SymmetricKey(size: .bits256)

        let someData = "SomeData".data(using: .utf8)!

        let mac = HMAC<SHA256>.authenticationCode(for: someData, using: key)
        XCTAssertFalse(mac == DispatchData.empty)
    }
}
#endif // (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM
