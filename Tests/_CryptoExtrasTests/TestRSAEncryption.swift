//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) YEARS Apple Inc. and the SwiftCrypto project authors
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
import Crypto
import _CryptoExtras

final class TestRSAEncryption: XCTestCase {
    
    func test_wycheproofOAEPVectors() throws {
        try wycheproofTest(
            jsonName: "rsa_oaep_misc_test",
            testFunction: self.testOAEPGroup)
        try wycheproofTest(
            jsonName: "rsa_oaep_2048_sha1_mgf1sha1_test",
            testFunction: self.testOAEPGroup)
        try wycheproofTest(
            jsonName: "rsa_oaep_2048_sha256_mgf1sha256_test",
            testFunction: self.testOAEPGroup)
    }
    
    private func testOAEPGroup(_ group: RSAEncryptionOAEPTestGroup) throws {
        let derPrivKey: _RSA.Encryption.PrivateKey
        let pemPrivKey: _RSA.Encryption.PrivateKey
        
        if group.keysize < 2048 {
            derPrivKey = try _RSA.Encryption.PrivateKey(unsafeDERRepresentation: group.privateKeyDerBytes)
            pemPrivKey = try _RSA.Encryption.PrivateKey(unsafePEMRepresentation: group.privateKeyPem)
        } else {
            derPrivKey = try _RSA.Encryption.PrivateKey(derRepresentation: group.privateKeyDerBytes)
            pemPrivKey = try _RSA.Encryption.PrivateKey(pemRepresentation: group.privateKeyPem)
        }

        XCTAssertEqual(derPrivKey.derRepresentation, pemPrivKey.derRepresentation)
        XCTAssertEqual(derPrivKey.pemRepresentation, pemPrivKey.pemRepresentation)

        let derPubKey = derPrivKey.publicKey

        let padding: _RSA.Encryption.Padding
        if group.sha == "SHA-1", group.mgfSha == "SHA-1" {
            padding = .PKCS1_OAEP
        } else if group.sha == "SHA-256", group.mgfSha == "SHA-256" {
            padding = .PKCS1_OAEP_SHA256
        } else {
            // We currently only support SHA-1, SHA-256.
            return
        }
        
        for test in group.tests {
            guard test.label?.isEmpty ?? true else {
                // We currently have no support for OAEP labels.
                continue
            }
            let valid: Bool

            do {
                let decryptResult = try derPrivKey.decrypt(test.ciphertextBytes, padding: padding)
                let encryptResult = try derPubKey.encrypt(test.messageBytes, padding: padding)
                let decryptResult2 = try derPrivKey.decrypt(encryptResult, padding: padding)

                valid = (test.messageBytes == decryptResult && decryptResult2 == decryptResult)
            } catch {
                valid = false
            }
            
            XCTAssertEqual(valid, test.expectedValidity, "test number \(test.tcId) failed, expected \(test.result) but got \(valid)")
        }
    }
    
    func testUnsafeKeySize() throws {
        try testUnsafeKeySize(1024)
        try testUnsafeKeySize(1536)
    }
    
    private func testUnsafeKeySize(_ keySizeInBits: Int) throws {
        XCTAssert(keySizeInBits >= 1024 && keySizeInBits < 2048, "Unsafe key size must be in the range [1024, 2048)")
        
        let privKey = try _RSA.Encryption.PrivateKey(unsafeKeySize: .init(bitCount: keySizeInBits))
        let derPrivKey = try _RSA.Encryption.PrivateKey(unsafeDERRepresentation: privKey.derRepresentation)
        XCTAssert(derPrivKey.keySizeInBits == keySizeInBits)
        let pemPrivKey = try _RSA.Encryption.PrivateKey(unsafePEMRepresentation: privKey.pemRepresentation)
        XCTAssert(pemPrivKey.keySizeInBits == keySizeInBits)
        
        let pubKey = privKey.publicKey
        let derPubKey = try _RSA.Encryption.PublicKey(unsafeDERRepresentation: pubKey.derRepresentation)
        XCTAssert(derPubKey.keySizeInBits == keySizeInBits)
        let pemPubKey = try _RSA.Encryption.PublicKey(unsafePEMRepresentation: pubKey.pemRepresentation)
        XCTAssert(pemPubKey.keySizeInBits == keySizeInBits)
    }
}

struct RSAEncryptionOAEPTestGroup: Codable {
    var privateKeyPem: String
    var privateKeyPkcs8: String
    var sha: String
    var tests: [RSAEncryptionTest]
    var mgfSha: String
    var keysize: Int

    var privateKeyDerBytes: Data {
        return try! Data(hexString: self.privateKeyPkcs8)
    }
}

struct RSAEncryptionTest: Codable {
    var tcId: Int
    var comment: String
    var msg: String
    var ct: String
    var result: String
    var flags: [String]
    var label: String?

    var messageBytes: Data {
        return try! Data(hexString: self.msg)
    }

    var ciphertextBytes: Data {
        return try! Data(hexString: self.ct)
    }

    var expectedValidity: Bool {
        switch self.result {
        case "valid":
            return true
        case "invalid":
            return false
        case "acceptable":
            return true
        default:
            fatalError("Unexpected validity")
        }
    }
}
