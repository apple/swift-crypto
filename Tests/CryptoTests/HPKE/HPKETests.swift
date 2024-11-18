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
import Foundation
import XCTest

#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// Skip tests that require @testable imports of CryptoKit.
#else
#if !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@testable import CryptoKit
#else
@testable import Crypto
#endif

class HPKETests: XCTestCase {
    func testCases() throws {
        let ciphersuitesToTest = [HPKE.Ciphersuite.P256_SHA256_AES_GCM_256, .P384_SHA384_AES_GCM_256, .P521_SHA512_AES_GCM_256, .Curve25519_SHA256_ChachaPoly]
        
        for ciphersuite in ciphersuitesToTest {
            try testCiphersuite(ciphersuite)
        }
    }
    
    func testMismatchedKEM() {
        let skR = P256.KeyAgreement.PrivateKey()
        XCTAssertThrowsError(try HPKE.Sender(recipientKey: skR.publicKey, ciphersuite: .P384_SHA384_AES_GCM_256, info: Data()))
    }
        
    func testCiphersuite(_ ciphersuite: HPKE.Ciphersuite) throws {
        switch ciphersuite.kem {
        case .P256_HKDF_SHA256:
            try testCiphersuite(ciphersuite, withKeys: P256.KeyAgreement.PrivateKey.self)
        case .P384_HKDF_SHA384:
            try testCiphersuite(ciphersuite, withKeys: P384.KeyAgreement.PrivateKey.self)
        case .P521_HKDF_SHA512:
            try testCiphersuite(ciphersuite, withKeys: P521.KeyAgreement.PrivateKey.self)
        case .Curve25519_HKDF_SHA256:
            try testCiphersuite(ciphersuite, withKeys: Curve25519.KeyAgreement.PrivateKey.self)
        }
        
    }
    
    func testCiphersuite<SK: HPKEDiffieHellmanPrivateKey>(_ c: HPKE.Ciphersuite, withKeys: SK.Type) throws {
        let skS = SK.PublicKey.EphemeralPrivateKey()
        let skR = SK.PublicKey.EphemeralPrivateKey()
        let info = Data("Some Test Data".utf8)
        
        let psk = SymmetricKey(size: .bits256)
        let pskID = Data(SHA256.hash(data: info))
        
        // Testing base mode
        var sender = try HPKE.Sender(recipientKey: skR.publicKey, ciphersuite: c, info: info)
        var recipient = try HPKE.Recipient(privateKey: skR, ciphersuite: c, info: info, encapsulatedKey: sender.encapsulatedKey)
        XCTAssertNoThrow(try testSenderRecipient(sender: &sender, recipient: &recipient))
        
        // Testing auth mode
        sender = try HPKE.Sender(recipientKey: skR.publicKey, ciphersuite: c, info: info, authenticatedBy: skS)
        recipient = try HPKE.Recipient(privateKey: skR, ciphersuite: c, info: info, encapsulatedKey: sender.encapsulatedKey, authenticatedBy: skS.publicKey)
        XCTAssertNoThrow(try testSenderRecipient(sender: &sender, recipient: &recipient))
        
        // Testing psk mode
        sender = try HPKE.Sender(recipientKey: skR.publicKey, ciphersuite: c, info: info, presharedKey: psk, presharedKeyIdentifier: pskID)
        recipient = try HPKE.Recipient(privateKey: skR, ciphersuite: c, info: info, encapsulatedKey: sender.encapsulatedKey, presharedKey: psk, presharedKeyIdentifier: pskID)
        XCTAssertNoThrow(try testSenderRecipient(sender: &sender, recipient: &recipient))
        
        // Testing auth_psk mod
        sender = try HPKE.Sender(recipientKey: skR.publicKey, ciphersuite: c, info: info, authenticatedBy: skS, presharedKey: psk, presharedKeyIdentifier: pskID)
        recipient = try HPKE.Recipient(privateKey: skR, ciphersuite: c, info: info, encapsulatedKey: sender.encapsulatedKey, authenticatedBy: skS.publicKey, presharedKey: psk, presharedKeyIdentifier: pskID)
        XCTAssertNoThrow(try testSenderRecipient(sender: &sender, recipient: &recipient))
    }
    
    func testSenderRecipient(sender: inout HPKE.Sender, recipient: inout HPKE.Recipient) throws {
        let msg = Data("Some Other Data".utf8)
        let aad = Data("Some Authenticated Data".utf8)
        XCTAssertEqual(sender.exporterSecret, recipient.exporterSecret)
        
        for _ in 0...100 {
            let ct = try sender.seal(msg, authenticating: msg)
            let pt = try recipient.open(ct, authenticating: msg)
            XCTAssertEqual(pt, msg)
        }
        
        var ct = try sender.seal(msg, authenticating: aad)
        XCTAssertEqual(try recipient.open(ct, authenticating: aad), msg)
        XCTAssertThrowsError(try recipient.open(ct, authenticating: aad))
        
        ct = try sender.seal(msg, authenticating: aad)
        XCTAssertEqual(try recipient.open(ct, authenticating: aad), msg)
        
        let aad2 = Data("inconsistentAAD".utf8)
        ct = try sender.seal(msg, authenticating: aad2)
        XCTAssertThrowsError(try recipient.open(ct, authenticating: aad))
        XCTAssertEqual(try recipient.open(ct, authenticating: aad2), msg)
    }
}

#endif // CRYPTO_IN_SWIFTPM
