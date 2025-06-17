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

#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// Skip tests that require @testable imports of CryptoKit.
#else
#if !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@testable @_spi(HPKEAlgID) import CryptoKit
@testable import CryptoKit
#else
@testable @_spi(HPKEAlgID) import Crypto
#endif

class HPKETests: XCTestCase {
    func testCases() throws {
        var ciphersuitesToTest = [
            HPKE.Ciphersuite.P256_SHA256_AES_GCM_256, .P384_SHA384_AES_GCM_256, .P521_SHA512_AES_GCM_256, .Curve25519_SHA256_ChachaPoly
        ]
        if #available(iOS 19.0, macOS 16.0, watchOS 12.0, tvOS 19.0, macCatalyst 19.0, *) {
            ciphersuitesToTest.append(contentsOf: [
                .XWingMLKEM768X25519_SHA256_AES_GCM_256
            ])
        }

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
        case .XWingMLKEM768X25519:
            if #available(iOS 19.0, macOS 16.0, watchOS 12.0, tvOS 19.0, macCatalyst 19.0, *) {
                try testHPKECiphersuite(ciphersuite, withKeys: XWingMLKEM768X25519.PrivateKey.self)
            } else { /* pass */ }
        @unknown default:
            fatalError()
        }
    }

    func testHPKECiphersuite<SK: HPKEKEMPrivateKey>(_ c: HPKE.Ciphersuite, withKeys: SK.Type) throws {
        let skR = try SK.PublicKey.EphemeralPrivateKey()
        let info = Data("Some Test Data".utf8)
        var sender = try HPKE.Sender(recipientKey: skR.publicKey, ciphersuite: c, info: info)
        var recipient = try HPKE.Recipient(privateKey: skR, ciphersuite: c, info: info, encapsulatedKey: sender.encapsulatedKey)
        XCTAssertNoThrow(try testSenderRecipient(sender: &sender, recipient: &recipient))
    }

    func testCiphersuite<SK: HPKEDiffieHellmanPrivateKey>(_ c: HPKE.Ciphersuite, withKeys: SK.Type) throws {
        let skS = SK.PublicKey.EphemeralPrivateKey()
        let skR = SK.PublicKey.EphemeralPrivateKey()
        let info = Data("Some Test Data".utf8)
        
        let psk = SymmetricKey(size: SymmetricKeySize.bits256)
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
        XCTAssertEqual(try sender.exportSecret(context: Data("SampleContext".utf8), outputByteCount: 16), try recipient.exportSecret(context: Data("SampleContext".utf8), outputByteCount: 16))
        
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
    
    func testHPKEIdentifiers() throws {
        /*
         HPKE.Ciphersuite.P256_SHA256_AES_GCM_256, .P384_SHA384_AES_GCM_256, .P521_SHA512_AES_GCM_256, .Curve25519_SHA256_ChachaPoly
         */
        let cp256 = HPKE.Ciphersuite.P256_SHA256_AES_GCM_256
        XCTAssertEqual(cp256.kem.value, 0x0010)
        XCTAssertEqual(cp256.kem.nEnc, 65)
        XCTAssertEqual(cp256.kdf.value, 0x0001)
        XCTAssertEqual(cp256.aead.value, 0x0002)
        XCTAssertEqual(cp256.aead.keyByteCount, 32)
        XCTAssertEqual(cp256.aead.nonceByteCount, 12)
        XCTAssertEqual(cp256.aead.tagByteCount, 16)
        
        let cp384 = HPKE.Ciphersuite.P384_SHA384_AES_GCM_256
        XCTAssertEqual(cp384.kem.value, 0x0011)
        XCTAssertEqual(cp384.kem.nEnc, 97)
        XCTAssertEqual(cp384.kdf.value, 0x0002)
        XCTAssertEqual(cp384.aead.value, 0x0002)
        
        let cp521 = HPKE.Ciphersuite.P521_SHA512_AES_GCM_256
        XCTAssertEqual(cp521.kem.value, 0x0012)
        XCTAssertEqual(cp521.kem.nEnc, 133)
        XCTAssertEqual(cp521.kdf.value, 0x0003)
        XCTAssertEqual(cp521.aead.value, 0x0002)
        
        let cc25519 = HPKE.Ciphersuite.Curve25519_SHA256_ChachaPoly
        XCTAssertEqual(cc25519.kem.value, 0x0020)
        XCTAssertEqual(cc25519.kem.nEnc, 32)
        XCTAssertEqual(cc25519.kdf.value, 0x0001)
        XCTAssertEqual(cc25519.aead.value, 0x0003)
        XCTAssertEqual(cc25519.aead.keyByteCount, 32)
        XCTAssertEqual(cc25519.aead.nonceByteCount, 12)
        XCTAssertEqual(cc25519.aead.tagByteCount, 16)
    }

    func testHPKEKEMInterface() throws {
        if #available(iOS 19.0, macOS 16.0, watchOS 12.0, tvOS 19.0, macCatalyst 19.0, *) {
            let c = HPKE.Ciphersuite.XWingMLKEM768X25519_SHA256_AES_GCM_256
            let skR = try XWingMLKEM768X25519.PrivateKey.generate()
            let info = Data("Some Test Data".utf8)
            var sender = try HPKE.Sender(recipientKey: skR.publicKey, ciphersuite: c, info: info)
            var recipient = try HPKE.Recipient(privateKey: skR, ciphersuite: c, info: info, encapsulatedKey: sender.encapsulatedKey)
            XCTAssertNoThrow(try testSenderRecipient(sender: &sender, recipient: &recipient))
        }
    }
}

#endif // CRYPTO_IN_SWIFTPM
