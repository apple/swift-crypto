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

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import XCTest

#if canImport(CryptoKit)
// Skip tests that require @testable imports of CryptoKit.
#else
@testable import Crypto

enum ECDHTestErrors: Error {
    case PublicKeyFailure
    case ParseSPKIFailure
}

class NISTECDHTests: XCTestCase {
    func testInteropFIPSKeys() throws {
        var fipsKey: P256.KeyAgreement.PrivateKey = P256.KeyAgreement.PrivateKey(compactRepresentable: false)
        for _ in 0...10_000 {
            fipsKey = P256.KeyAgreement.PrivateKey(compactRepresentable: false)
            
            // We ensure we have a key that's not compact representable. (Some FIPS keys are)
            if fipsKey.publicKey.compactRepresentation != nil {
                continue
            } else {
                break
            }
        }
        
        let compactKey = P256.KeyAgreement.PrivateKey(compactRepresentable: true)
        
        XCTAssertNil(fipsKey.publicKey.compactRepresentation)
        XCTAssertNotNil(compactKey.publicKey.compactRepresentation)
        
        let ss1 = try orFail { try fipsKey.sharedSecretFromKeyAgreement(with: compactKey.publicKey) }
        let ss2 = try orFail { try compactKey.sharedSecretFromKeyAgreement(with: fipsKey.publicKey) }
        XCTAssertEqual(ss1, ss2)
        
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(compactRepresentation: fipsKey.publicKey.rawRepresentation))
        let compactRepresentation = try unwrap(compactKey.publicKey.compactRepresentation)
        XCTAssertNotNil(try P256.KeyAgreement.PublicKey(compactRepresentation: compactRepresentation))
    }
    
    func testWycheproof() throws {
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdh_secp256r1_test",
                testFunction: { (group: ECDHTestGroup) in
                    testGroup(group: group, privateKeys: P256.KeyAgreement.PrivateKey.self, onCurve: P256.self)
                })
        }
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdh_secp384r1_test",
                testFunction: { (group: ECDHTestGroup) in
                    testGroup(group: group, privateKeys: P384.KeyAgreement.PrivateKey.self, onCurve: P384.self)
                })
        }
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdh_secp521r1_test",
                testFunction: { (group: ECDHTestGroup) in
                    testGroup(group: group, privateKeys: P521.KeyAgreement.PrivateKey.self, onCurve: P521.self)
                })
        }

        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdh_secp256r1_ecpoint_test",
                testFunction: { (group: ECDHTestGroup) in
                    testGroupPoint(group: group, privateKeys: P256.KeyAgreement.PrivateKey.self, onCurve: P256.self)
                })
        }
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdh_secp384r1_ecpoint_test",
                testFunction: { (group: ECDHTestGroup) in
                    testGroupPoint(group: group, privateKeys: P384.KeyAgreement.PrivateKey.self, onCurve: P384.self)
                })
        }
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "ecdh_secp521r1_ecpoint_test",
                testFunction: { (group: ECDHTestGroup) in
                    testGroupPoint(group: group, privateKeys: P521.KeyAgreement.PrivateKey.self, onCurve: P521.self)
                })
        }
    }
    
    func testGroup<PrivKey: NISTECPrivateKey & DiffieHellmanKeyAgreement, Curve: SupportedCurveDetailsImpl>(group: ECDHTestGroup, privateKeys: PrivKey.Type, onCurve curve: Curve.Type) {
        self.testGroupOpenSSL(group: group, privateKeys: privateKeys, onCurve: curve)
    }

    func testGroupPoint<PrivKey: NISTECPrivateKey & DiffieHellmanKeyAgreement, Curve: SupportedCurveDetailsImpl>(group: ECDHTestGroup, privateKeys: PrivKey.Type, onCurve curve: Curve.Type) {
        self.testGroupPointOpenSSL(group: group, privateKeys: privateKeys, onCurve: curve)
    }
}
#endif // canImport(CryptoKit)
