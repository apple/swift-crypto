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
            jsonName: "rsa_oaep_2048_sha1_mgf1sha1_test",
            testFunction: self.testOAEPGroup)
        try wycheproofTest(
            jsonName: "rsa_oaep_misc_test",
            testFunction: self.testOAEPGroup)
    }
    
    private func testOAEPGroup(_ group: RSAEncryptionOAEPTestGroup) throws {
        let derPrivKey = try _RSA.Signing.PrivateKey(derRepresentation: group.privateKeyDerBytes)
        let pemPrivKey = try _RSA.Signing.PrivateKey(pemRepresentation: group.privateKeyPem)

        XCTAssertEqual(derPrivKey.derRepresentation, pemPrivKey.derRepresentation)
        XCTAssertEqual(derPrivKey.pemRepresentation, pemPrivKey.pemRepresentation)

        let derPubKey = derPrivKey.publicKey

        guard group.sha == "SHA-1", group.mgfSha == "SHA-1" else {
            // We currently only support SHA-1 OAEP, which is very legacy but oh well.
            return
        }
        
        for test in group.tests {
            guard test.label?.isEmpty ?? true else {
                // We currently have no support for OAEP labels.
                continue
            }
            let valid: Bool
            
            do {
                let decryptResult = try derPrivKey.decrypt(test.ciphertextBytes, padding: .PKCS1_OAEP)
                let encryptResult = try derPubKey.encrypt(test.messageBytes, padding: .PKCS1_OAEP)
                let decryptResult2 = try derPrivKey.decrypt(encryptResult.rawRepresentation, padding: .PKCS1_OAEP)
                
                valid = (test.messageBytes == decryptResult.rawRepresentation && decryptResult2.rawRepresentation == decryptResult.rawRepresentation)
            } catch {
                valid = false
            }
            
            XCTAssertEqual(valid, test.expectedValidity, "test number \(test.tcId) failed, expected \(test.result) but got \(valid)")
        }
    }
}

struct RSAEncryptionOAEPTestGroup: Codable {
    var privateKeyPem: String
    var privateKeyPkcs8: String
    var sha: String
    var tests: [RSAEncryptionTest]
    var mgfSha: String

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
