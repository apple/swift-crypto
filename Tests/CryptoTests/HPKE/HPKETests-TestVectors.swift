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
#else
@testable @_spi(HPKEAlgID) import Crypto
#endif

// Curve448 is not supported on our platforms
let unsupportedKEMs: [UInt16] = [0x0021]

struct HPKETestEncryption: Codable {
    let aad: String
    let ct: String
    let nonce: String
    let pt: String
}

struct HPKETestVector: Codable {
    let mode: UInt8
    let kem_id: UInt16
    let kdf_id: UInt16
    let aead_id: UInt16
    
    let info: String
    let enc: String
    
    let skEm: String
    let skRm: String
    
    let pkEm: String
    let pkRm: String
    
    let pkSm: String?
    
    let psk: String?
    let psk_id: String?
    
    let shared_secret: String
    let secret: String
    
    let exporter_secret: String
    
    let encryptions: [HPKETestEncryption]
}

class HPKETestVectors: XCTestCase {
    
    func testVectors() throws {
        #if !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        let bundle = Bundle(for: type(of: self))
        #else
        let bundle = Bundle.module
        #endif
        let fileURL = bundle.url(forResource: "hpke-test-vectors", withExtension: "json")!
        let data = try orFail { try Data(contentsOf: fileURL) }
        let decoder = JSONDecoder()
        let testVectors = try orFail { try decoder.decode([HPKETestVector].self, from: data) }
        testVectors.forEach { validateTestVector($0) }
    }
    
    func validateTestVector(_ tv: HPKETestVector) {
        guard let ciphersuite = ciphersuiteFromValues(kemValue: tv.kem_id, kdfValue: tv.kdf_id, aeadValue: tv.aead_id) else {
            if unsupportedKEMs.contains(tv.kem_id) {
                print("Skipping unsupported KEM: \(tv.kem_id)")
            } else {
                XCTFail("Ciphersuite coulnd't be configured from input values kem:\(tv.kem_id) kdf:\(tv.kdf_id) aead: \(tv.aead_id)")
            }
            return
        }
        
        let skRBytes = try! Data(hexString: tv.skRm)
        
        switch ciphersuite.kem {
        case .P256_HKDF_SHA256:
            XCTAssertNoThrow(try testWithKEM(tv, ciphersuite: ciphersuite, skR: P256.KeyAgreement.PrivateKey(rawRepresentation: skRBytes)))
        case .P384_HKDF_SHA384:
            XCTAssertNoThrow(try testWithKEM(tv, ciphersuite: ciphersuite, skR: P384.KeyAgreement.PrivateKey(rawRepresentation: skRBytes)))
        case .P521_HKDF_SHA512:
            XCTAssertNoThrow(try testWithKEM(tv, ciphersuite: ciphersuite, skR: P521.KeyAgreement.PrivateKey(rawRepresentation: skRBytes)))
        case .Curve25519_HKDF_SHA256:
            XCTAssertNoThrow(try testWithKEM(tv, ciphersuite: ciphersuite, skR: Curve25519.KeyAgreement.PrivateKey(rawRepresentation: skRBytes)))
        case .XWingMLKEM768X25519:
            // There are no test vectors for this implementation
            break
        }
    }
    
    func testWithKEM<SK: HPKEDiffieHellmanPrivateKey>(_ tv: HPKETestVector, ciphersuite: HPKE.Ciphersuite, skR: SK) throws {
        let encapsulated = try Data(hexString: tv.enc)
                
        switch tv.mode {
        case HPKE.Mode.base.value, HPKE.Mode.psk.value: do {
            try testUnauthenticatedModesWithKeys(tv, ciphersuite: ciphersuite, skR: skR, encapsulated: encapsulated)
        }
        case HPKE.Mode.auth.value, HPKE.Mode.auth_psk.value: do {
            let pkSBytes = try Data(hexString: tv.pkSm!)
            let pkS = try SK.PublicKey(pkSBytes, kem: ciphersuite.kem)
            
            try testAuthenticatedModesWithKeys(tv, ciphersuite: ciphersuite, skR: skR, encapsulated: encapsulated, pkS: pkS)
        }
        default:
            XCTFail("Test vectors contain an unsupported mode.")
        }
    }
    
    func testUnauthenticatedModesWithKeys<PrivateKey: HPKEDiffieHellmanPrivateKey>(_ tv: HPKETestVector, ciphersuite: HPKE.Ciphersuite, skR: PrivateKey, encapsulated: Data) throws {
        let infoBytes = try Data(hexString: tv.info)
                
        var recipient: HPKE.Recipient
        if tv.mode == HPKE.Mode.base.value {
            print(try skR.publicKey.hpkeRepresentation(kem: ciphersuite.kem).hexString)
            recipient = try! HPKE.Recipient(privateKey: skR, ciphersuite: ciphersuite, info: infoBytes, encapsulatedKey: encapsulated)
        } else {
            let psk = try SymmetricKey(data: Data(hexString: tv.psk!))
            let psk_id = try Data(hexString: tv.psk_id!)
            recipient = try! HPKE.Recipient(privateKey: skR, ciphersuite: ciphersuite, info: infoBytes, encapsulatedKey: encapsulated, presharedKey: psk, presharedKeyIdentifier: psk_id)
        }
        
        XCTAssertEqual(recipient.exporterSecret.withUnsafeBytes { Data($0) }.hexString, tv.exporter_secret)
        try testEncryptions(tv.encryptions, with: &recipient)
    }
    
    func testAuthenticatedModesWithKeys<SK: HPKEDiffieHellmanPrivateKey>(_ tv: HPKETestVector, ciphersuite: HPKE.Ciphersuite, skR: SK, encapsulated: Data, pkS: SK.PublicKey) throws {
        let infoBytes = try Data(hexString: tv.info)
        
        var recipient: HPKE.Recipient
        if tv.mode == HPKE.Mode.auth.value {
            recipient = try! HPKE.Recipient(privateKey: skR, ciphersuite: ciphersuite, info: infoBytes, encapsulatedKey: encapsulated, authenticatedBy: pkS)
        } else {
            let psk = try SymmetricKey(data: Data(hexString: tv.psk!))
            let psk_id = try Data(hexString: tv.psk_id!)
            recipient = try! HPKE.Recipient(privateKey: skR, ciphersuite: ciphersuite, info: infoBytes, encapsulatedKey: encapsulated, authenticatedBy: pkS, presharedKey: psk, presharedKeyIdentifier: psk_id)
        }

        XCTAssertEqual(recipient.exporterSecret.withUnsafeBytes { Data($0) }.hexString, tv.exporter_secret)
        try testEncryptions(tv.encryptions, with: &recipient)
    }
    
    func testEncryptions(_ encryptions: [HPKETestEncryption], with recipient: inout HPKE.Recipient) throws {
        for encryption in encryptions {
            let ct = try Data(hexString: encryption.ct)
            let aad = try Data(hexString: encryption.aad)
            let pt = try Data(hexString: encryption.pt)
            
            XCTAssertEqual(try recipient.open(ct, authenticating: aad), pt)
        }
    }
}

private func ciphersuiteFromValues(kemValue: UInt16,
                                   kdfValue: UInt16,
                                   aeadValue: UInt16) -> HPKE.Ciphersuite? {
    let kem = kemFromValue(value: kemValue)
    let kdf = kdfFromValue(value: kdfValue)
    let aead = aeadFromValue(value: aeadValue)
    
    if kem != nil && kdf != nil && aead != nil {
        return HPKE.Ciphersuite(kem: kem!, kdf: kdf!, aead: aead!)
    }
    return nil
}

private func kemFromValue(value: UInt16) -> HPKE.KEM? {
    var kemValues = HPKE.KEM.allCases
    kemValues = kemValues.filter { value == $0.value }
    return kemValues.first
}

private func kdfFromValue(value: UInt16) -> HPKE.KDF? {
    var kdfValues = HPKE.KDF.allCases
    kdfValues = kdfValues.filter { value == $0.value }
    return kdfValues.first
}

private func aeadFromValue(value: UInt16) -> HPKE.AEAD? {
    var aeadValues = HPKE.AEAD.allCases
    aeadValues = aeadValues.filter { value == $0.value }
    return aeadValues.first
}

#endif // CRYPTO_IN_SWIFTPM
