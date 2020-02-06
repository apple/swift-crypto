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
import Foundation
import XCTest

#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// Skip tests that require @testable imports of CryptoKit.
#else
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@testable import CryptoKit
#else
@testable import Crypto
#endif

struct ECDHTestGroup: Codable {
    let curve: String
    let tests: [ECDHTestVector]
}

struct ECDHTestVector: Codable {
    let comment: String
    let publicKey: String
    let privateKey: String
    let shared: String
    let result: String
    let tcId: Int
    let flags: [String]

    enum CodingKeys: String, CodingKey {
        case publicKey = "public"
        case privateKey = "private"
        case comment
        case shared
        case result
        case tcId
        case flags
    }
}

class X25519Tests: XCTestCase {
    func testSerialization() throws {
        let bobsKey = Curve25519.KeyAgreement.PrivateKey()
        
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let keyData = privateKey.rawRepresentation
        
        let recoveredKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: keyData)
        
        let ss1 = try! privateKey.sharedSecretFromKeyAgreement(with: bobsKey.publicKey)
        let ss2 = try! recoveredKey.sharedSecretFromKeyAgreement(with: bobsKey.publicKey)
        
        XCTAssert(ss1 == ss2)
        XCTAssert(recoveredKey.rawRepresentation == keyData)
    }
    
    func testWycheproof() throws {
        wycheproofTest(bundleType: self,
                       jsonName: "x25519_test",
                       testFunction: { (group: ECDHTestGroup) in
                        try! testGroup(group: group)
        })
    }

    func testGroup(group: ECDHTestGroup) throws {
        for testVector in group.tests {
            let publicKey = try! Curve25519.KeyAgreement.PublicKey(rawRepresentation: Array(hexString: testVector.publicKey))
            let privateKey = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Array(hexString: testVector.privateKey))

            do {
                let expectedSharedSecret = try Array(hexString: testVector.shared)

                XCTAssert(try Array(privateKey.sharedSecretFromKeyAgreement(with: publicKey).ss) == expectedSharedSecret)
            } catch {
                XCTAssert(testVector.result == "invalid")
            }
        }
    }
}

#endif // (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM
