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
import XCTest

#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// Skip tests that require @testable imports of CryptoKit.
#else
#if !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@testable import CryptoKit
#else
@testable import Crypto
#endif

class ECKeyEncodingsTests: XCTestCase {
    func testEncodingsKeyAgreement() {
        let p256KeyKA = P256.KeyAgreement.PrivateKey()
        let p256KeyKA_raw = p256KeyKA.rawRepresentation
        let p256KeyKA_x963 = p256KeyKA.x963Representation
        XCTAssertNoThrow(try P256.KeyAgreement.PrivateKey(rawRepresentation: p256KeyKA_raw))
        XCTAssertNoThrow(try P256.KeyAgreement.PrivateKey(x963Representation: p256KeyKA_x963))
        
        let p384KeyKA = P384.KeyAgreement.PrivateKey()
        let p384KeyKA_raw = p384KeyKA.rawRepresentation
        let p384KeyKA_x963 = p384KeyKA.x963Representation
        XCTAssertNoThrow(try P384.KeyAgreement.PrivateKey(rawRepresentation: p384KeyKA_raw))
        XCTAssertNoThrow(try P384.KeyAgreement.PrivateKey(x963Representation: p384KeyKA_x963))
        
        let p521KeyKA = P521.KeyAgreement.PrivateKey()
        let p521KeyKA_raw = p521KeyKA.rawRepresentation
        let p521KeyKA_x963 = p521KeyKA.x963Representation
        XCTAssertNoThrow(try P521.KeyAgreement.PrivateKey(rawRepresentation: p521KeyKA_raw))
        XCTAssertNoThrow(try P521.KeyAgreement.PrivateKey(x963Representation: p521KeyKA_x963))
        
        // Curve25519 does not have an x963 representation.
        let x25519KeyKA = Curve25519.KeyAgreement.PrivateKey()
        let x25519KeyKA_raw = x25519KeyKA.rawRepresentation
        XCTAssertNoThrow(try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: x25519KeyKA_raw))
    }
    
    func testEncodingsSigningKeyTests() {
        let p256KeyKA = P256.Signing.PrivateKey()
        let p256KeyKA_raw = p256KeyKA.rawRepresentation
        let p256KeyKA_x963 = p256KeyKA.x963Representation
        XCTAssertNoThrow(try P256.Signing.PrivateKey(rawRepresentation: p256KeyKA_raw))
        XCTAssertNoThrow(try P256.Signing.PrivateKey(x963Representation: p256KeyKA_x963))
        
        let p384KeyKA = P384.Signing.PrivateKey()
        let p384KeyKA_raw = p384KeyKA.rawRepresentation
        let p384KeyKA_x963 = p384KeyKA.x963Representation
        XCTAssertNoThrow(try P384.Signing.PrivateKey(rawRepresentation: p384KeyKA_raw))
        XCTAssertNoThrow(try P384.Signing.PrivateKey(x963Representation: p384KeyKA_x963))
        
        let p521KeyKA = P521.Signing.PrivateKey()
        let p521KeyKA_raw = p521KeyKA.rawRepresentation
        let p521KeyKA_x963 = p521KeyKA.x963Representation
        XCTAssertNoThrow(try P521.Signing.PrivateKey(rawRepresentation: p521KeyKA_raw))
        XCTAssertNoThrow(try P521.Signing.PrivateKey(x963Representation: p521KeyKA_x963))
        
        let x25519KeyKA = Curve25519.Signing.PrivateKey()
        let x25519KeyKA_raw = x25519KeyKA.rawRepresentation
        XCTAssertNoThrow(try Curve25519.Signing.PrivateKey(rawRepresentation: x25519KeyKA_raw))
    }
    
    func testEncodingsKeyAgreementPublicKeys() {
        let p256KeyKA = P256.KeyAgreement.PrivateKey().publicKey
        let p256KeyKA_raw = p256KeyKA.rawRepresentation
        let p256KeyKA_x963 = p256KeyKA.x963Representation
        let p256KeyKA_compressed = p256KeyKA.compressedRepresentation
        XCTAssertNoThrow(try P256.KeyAgreement.PublicKey(rawRepresentation: p256KeyKA_raw))
        XCTAssertNoThrow(try P256.KeyAgreement.PublicKey(x963Representation: p256KeyKA_x963))
        XCTAssertNoThrow(try P256.KeyAgreement.PublicKey(compressedRepresentation: p256KeyKA_compressed))
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(compressedRepresentation: p256KeyKA_x963),
                             error: CryptoKitError.incorrectParameterSize)

        let p384KeyKA = P384.KeyAgreement.PrivateKey().publicKey
        let p384KeyKA_raw = p384KeyKA.rawRepresentation
        let p384KeyKA_x963 = p384KeyKA.x963Representation
        let p384KeyKA_compressed = p384KeyKA.compressedRepresentation
        XCTAssertNoThrow(try P384.KeyAgreement.PublicKey(rawRepresentation: p384KeyKA_raw))
        XCTAssertNoThrow(try P384.KeyAgreement.PublicKey(x963Representation: p384KeyKA_x963))
        XCTAssertNoThrow(try P384.KeyAgreement.PublicKey(compressedRepresentation: p384KeyKA_compressed))
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(compressedRepresentation: p384KeyKA_x963),
                             error: CryptoKitError.incorrectParameterSize)

        let p521KeyKA = P521.KeyAgreement.PrivateKey().publicKey
        let p521KeyKA_raw = p521KeyKA.rawRepresentation
        let p521KeyKA_x963 = p521KeyKA.x963Representation
        let p521KeyKA_compressed = p521KeyKA.compressedRepresentation
        XCTAssertNoThrow(try P521.KeyAgreement.PublicKey(rawRepresentation: p521KeyKA_raw))
        XCTAssertNoThrow(try P521.KeyAgreement.PublicKey(x963Representation: p521KeyKA_x963))
        XCTAssertNoThrow(try P521.KeyAgreement.PublicKey(compressedRepresentation: p521KeyKA_compressed))
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(compressedRepresentation: p521KeyKA_x963),
                             error: CryptoKitError.incorrectParameterSize)

        // Curve25519 does not have an x963 representation.
        let x25519KeyKA = Curve25519.KeyAgreement.PrivateKey().publicKey
        let x25519KeyKA_raw = x25519KeyKA.rawRepresentation
        XCTAssertNoThrow(try Curve25519.KeyAgreement.PublicKey(rawRepresentation: x25519KeyKA_raw))
    }
    
    func testEncodingsSigningKeyPublicKeys() {
        let p256KeyKA = P256.Signing.PrivateKey().publicKey
        let p256KeyKA_raw = p256KeyKA.rawRepresentation
        let p256KeyKA_x963 = p256KeyKA.x963Representation
        let p256KeyKA_compressed = p256KeyKA.compressedRepresentation

        XCTAssertNoThrow(try P256.Signing.PublicKey(rawRepresentation: p256KeyKA_raw))
        XCTAssertNoThrow(try P256.Signing.PublicKey(x963Representation: p256KeyKA_x963))
        XCTAssertNoThrow(try P256.KeyAgreement.PublicKey(compressedRepresentation: p256KeyKA_compressed))
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(compressedRepresentation: p256KeyKA_x963),
                             error: CryptoKitError.incorrectParameterSize)

        let p384KeyKA = P384.Signing.PrivateKey().publicKey
        let p384KeyKA_raw = p384KeyKA.rawRepresentation
        let p384KeyKA_x963 = p384KeyKA.x963Representation
        let p384KeyKA_compressed = p384KeyKA.compressedRepresentation
        XCTAssertNoThrow(try P384.Signing.PublicKey(rawRepresentation: p384KeyKA_raw))
        XCTAssertNoThrow(try P384.Signing.PublicKey(x963Representation: p384KeyKA_x963))
        XCTAssertNoThrow(try P384.KeyAgreement.PublicKey(compressedRepresentation: p384KeyKA_compressed))
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(compressedRepresentation: p384KeyKA_x963),
                             error: CryptoKitError.incorrectParameterSize)

        let p521KeyKA = P521.Signing.PrivateKey().publicKey
        let p521KeyKA_raw = p521KeyKA.rawRepresentation
        let p521KeyKA_x963 = p521KeyKA.x963Representation
        let p521KeyKA_compressed = p521KeyKA.compressedRepresentation
        XCTAssertNoThrow(try P521.Signing.PublicKey(rawRepresentation: p521KeyKA_raw))
        XCTAssertNoThrow(try P521.Signing.PublicKey(x963Representation: p521KeyKA_x963))
        XCTAssertNoThrow(try P521.KeyAgreement.PublicKey(compressedRepresentation: p521KeyKA_compressed))
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(compressedRepresentation: p521KeyKA_x963),
                             error: CryptoKitError.incorrectParameterSize)

        let x25519KeyKA = Curve25519.Signing.PrivateKey().publicKey
        let x25519KeyKA_raw = x25519KeyKA.rawRepresentation
        XCTAssertNoThrow(try Curve25519.Signing.PublicKey(rawRepresentation: x25519KeyKA_raw))
    }
    
    func testEncodingsKeyAgreementCompactRepresentation() {
        let p256KeyKA = P256.KeyAgreement.PrivateKey(compactRepresentable: true).publicKey
        let p256KeyKA_compact = p256KeyKA.compactRepresentation!
        XCTAssertNoThrow(try P256.KeyAgreement.PublicKey(compactRepresentation: p256KeyKA_compact))
        
        let p384KeyKA = P384.KeyAgreement.PrivateKey(compactRepresentable: true).publicKey
        let p384KeyKA_compact = p384KeyKA.compactRepresentation!
        XCTAssertNoThrow(try P384.KeyAgreement.PublicKey(compactRepresentation: p384KeyKA_compact))
        
        let p521KeyKA = P521.KeyAgreement.PrivateKey(compactRepresentable: true).publicKey
        let p521KeyKA_compact = p521KeyKA.compactRepresentation!
        XCTAssertNoThrow(try P521.KeyAgreement.PublicKey(compactRepresentation: p521KeyKA_compact))
    }
    
    func testEncodingsSigningCompactRepresentation() {
        let p256KeyKA = P256.Signing.PrivateKey(compactRepresentable: true).publicKey
        let p256KeyKA_compact = p256KeyKA.compactRepresentation!
        XCTAssertNoThrow(try P256.Signing.PublicKey(compactRepresentation: p256KeyKA_compact))
        
        let p384KeyKA = P384.Signing.PrivateKey(compactRepresentable: true).publicKey
        let p384KeyKA_compact = p384KeyKA.compactRepresentation!
        XCTAssertNoThrow(try P384.Signing.PublicKey(compactRepresentation: p384KeyKA_compact))
        
        let p521KeyKA = P521.Signing.PrivateKey(compactRepresentable: true).publicKey
        let p521KeyKA_compact = p521KeyKA.compactRepresentation!
        XCTAssertNoThrow(try P521.Signing.PublicKey(compactRepresentation: p521KeyKA_compact))
    }
    
    func testPEMPrivateKeyImport() throws {
        let pemKeyString = """
            -----BEGIN PRIVATE KEY-----
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNjSvGphHdpvWvUNB
            RR7xtcT7lQwt/VvTNYP+qTeinIqhRANCAAQLlT9xVWd72j6QQOIyXFhgwASrh1G1
            lyaDq/mR7r2Xasd+X1xm5P364yPecJJeFtDFYrTCeFa+d8/MvWDZQ0q5
            -----END PRIVATE KEY-----
            """
        XCTAssertNotNil(try P256.KeyAgreement.PrivateKey(pemRepresentation: pemKeyString))
    }
    
    func testDERPrivateKeyImport() throws {
        let derKey = Data(base64urlEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzdwpYwaEoIXKGBU_QHIJBgR4krKcxUgZsXDaarhEGXuhRANCAAT4A-8-QanrFJDb_bQVAEQcWM7HWeZh-hA1a6YvZi0-jq7LqSZOSnwteb4yDqbQ_USNWDlz6793Tr1kKDYjaK6L")!
        
        XCTAssertNotNil(try P256.KeyAgreement.PrivateKey(derRepresentation: derKey))
    }
    
    func testSimplePEMP256SPKI() throws {
        let pemPublicKey = """
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb4nB0k8CBVnKCHVHkxuXAkSlZuO5
    Nsev1rzcRv5QHiJuWUKomFGadQlMSGwoDOHEDdW3ujcA6t0ADteHw6KrZg==
    -----END PUBLIC KEY-----
    """
        
        // Test the working public keys.
        let signingKey = try orFail { try P256.Signing.PublicKey(pemRepresentation: pemPublicKey) }
        let keyAgreementKey = try orFail { try P256.KeyAgreement.PublicKey(pemRepresentation: pemPublicKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)
        
        // Now the non-matching public keys.
        XCTAssertThrowsError(try P384.Signing.PublicKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitError.incorrectParameterSize)
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitError.incorrectParameterSize)
        XCTAssertThrowsError(try P521.Signing.PublicKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitError.incorrectParameterSize)
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitError.incorrectParameterSize)

        // Now the private keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P384.Signing.PrivateKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P521.Signing.PrivateKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)

        // Validate we can reserialize.
        let firstReserialization = signingKey.pemRepresentation
        let secondReserialization = keyAgreementKey.pemRepresentation
        XCTAssertEqual(firstReserialization, pemPublicKey)
        XCTAssertEqual(secondReserialization, pemPublicKey)
    }
    
    func testSimplePEMP384SPKI() throws {
        let pemPublicKey = """
    -----BEGIN PUBLIC KEY-----
    MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEBwY0l7mq7hSBEZRld5ISWfSoFsYN3wwM
    hdD3cMU95DmYXzbqVHB4dCfsy7bexm4h9c0zs4CyTPzy3DV3vfmv1akQJIQv7l08
    lx/YXNeGXTN4Gr9r4rwA5GvRl1p6plPL
    -----END PUBLIC KEY-----
    """
        
        // Test the working public keys.
        let signingKey = try orFail { try P384.Signing.PublicKey(pemRepresentation: pemPublicKey) }
        let keyAgreementKey = try orFail { try P384.KeyAgreement.PublicKey(pemRepresentation: pemPublicKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)
        
        // Now the non-matching public keys.
        XCTAssertThrowsError(try P256.Signing.PublicKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitError.incorrectParameterSize)
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitError.incorrectParameterSize)
        XCTAssertThrowsError(try P521.Signing.PublicKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitError.incorrectParameterSize)
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitError.incorrectParameterSize)

        // Now the private keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P384.Signing.PrivateKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P521.Signing.PrivateKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)

        // Validate we can reserialize.
        let firstReserialization = signingKey.pemRepresentation
        let secondReserialization = keyAgreementKey.pemRepresentation
        XCTAssertEqual(firstReserialization, pemPublicKey)
        XCTAssertEqual(secondReserialization, pemPublicKey)
    }
    
    func testSimplePEMP521SPKI() throws {
        let pemPublicKey = """
    -----BEGIN PUBLIC KEY-----
    MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAp3v1UQWvSyQnkAUEBu+x/7ZrPtNJ
    SCUk9kMvuZMyGP1idwvspALuJjzrSFFlXObjlOjxucSbWhTYF/o3nc0XzpAA3dxA
    BYiMqH9vrVePoJMpv+DMdkUiUJ/WqHSOu9bJEi1h4fdqh5HHx4QZJY/iX/59VAi1
    uSbAhALvbdGFbVpkcOs=
    -----END PUBLIC KEY-----
    """
        
        // Test the working public keys.
        let signingKey = try orFail { try P521.Signing.PublicKey(pemRepresentation: pemPublicKey) }
        let keyAgreementKey = try orFail { try P521.KeyAgreement.PublicKey(pemRepresentation: pemPublicKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)
        
        // Now the non-matching public keys.
        XCTAssertThrowsError(try P256.Signing.PublicKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitError.incorrectParameterSize)
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitError.incorrectParameterSize)
        XCTAssertThrowsError(try P384.Signing.PublicKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitError.incorrectParameterSize)
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitError.incorrectParameterSize)

        // Now the private keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P384.Signing.PrivateKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P521.Signing.PrivateKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(pemRepresentation: pemPublicKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)

        // Validate we can reserialize.
        let firstReserialization = signingKey.pemRepresentation
        let secondReserialization = keyAgreementKey.pemRepresentation
        XCTAssertEqual(firstReserialization, pemPublicKey)
        XCTAssertEqual(secondReserialization, pemPublicKey)
    }
    
    func testSimplePEMP256PKCS8() throws {
        let pemPrivateKey = """
    -----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZjQLlzempZx7YF1F
    +MK1HWZTNgLcC1MAufb/2/YZYk6hRANCAAQwgn0PfkIHiZ/K+3zA//CoDqU2PqDc
    aA3U5R68jmlZQITvMyBlMJl9Mjh0biIe88dAfRKeUm9FVMD2ErJ/006V
    -----END PRIVATE KEY-----
    """
        
        // Test the working private keys.
        let signingKey = try orFail { try P256.Signing.PrivateKey(pemRepresentation: pemPrivateKey) }
        let keyAgreementKey = try orFail { try P256.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)
        
        // Now the non-matching private keys.
        XCTAssertThrowsError(try P384.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P521.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))
        
        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P384.Signing.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P521.Signing.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)

        // Validate we can reserialize.
        let firstReserialization = signingKey.pemRepresentation
        let secondReserialization = keyAgreementKey.pemRepresentation
        XCTAssertEqual(firstReserialization, pemPrivateKey)
        XCTAssertEqual(secondReserialization, pemPrivateKey)
    }
    
    func testSimplePEMP384PKCS8() throws {
        let pemPrivateKey = """
    -----BEGIN PRIVATE KEY-----
    MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDB7ERKhMR+mvz1NQ+oL
    i6ZJMACOcwbUetWcNnB4Mnx3j4XuhpkkHEW8E1+rXyjZ3UmhZANiAASYH+emlyXM
    kBSFJl0BiopDVuIIR47M4pLl00YNnuu/Rp5VHeVAHrP67i2Q92u5fk34eOSwQvkO
    VvktWsgtzAomIam4SHqE9bhvrHy6kW6QzxlERHTL+YkXEX8c6t8VOxk=
    -----END PRIVATE KEY-----
    """
        
        // Test the working private keys.
        let signingKey = try orFail { try P384.Signing.PrivateKey(pemRepresentation: pemPrivateKey) }
        let keyAgreementKey = try orFail { try P384.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)
        
        // Now the non-matching private keys.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P521.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))
        
        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P384.Signing.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P521.Signing.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)

        // Validate we can reserialize.
        let firstReserialization = signingKey.pemRepresentation
        let secondReserialization = keyAgreementKey.pemRepresentation
        XCTAssertEqual(firstReserialization, pemPrivateKey)
        XCTAssertEqual(secondReserialization, pemPrivateKey)
    }
    
    func testSimplePEMP521PKCS8() throws {
        let pemPrivateKey = """
    -----BEGIN PRIVATE KEY-----
    MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAmMp6YYRfT6uA+DFi
    VB/V7FGAgjjuin1GcF8eujBZTcNB8jyzyXfG7Ak80jd3yhrHhAg7rOOZYV72Ekz5
    o05NKM2hgYkDgYYABAEIOePr9DPc9lGHqSYrGHX0ICvZxy3DLTjPcl7jgAcUU9NT
    1DBvJ7aAAmzTImz9mKOJk14f1fxc1BsWjsf1hU4QOwFu1l+dIDcNYFUxjzsGMc5e
    LsSxRn35ts4qogmz3kmerOc0smI8NIFiK/EuinK5Bs8PfPMW3ZOCIpvXbqyksLk0
    rg==
    -----END PRIVATE KEY-----
    """
        
        // Test the working private keys.
        let signingKey = try orFail { try P521.Signing.PrivateKey(pemRepresentation: pemPrivateKey) }
        let keyAgreementKey = try orFail { try P521.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)
        
        // Now the non-matching private keys.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P384.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))
        
        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P384.Signing.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P521.Signing.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)

        // Validate we can reserialize.
        let firstReserialization = signingKey.pemRepresentation
        let secondReserialization = keyAgreementKey.pemRepresentation
        XCTAssertEqual(firstReserialization, pemPrivateKey)
        XCTAssertEqual(secondReserialization, pemPrivateKey)
    }
    
    func testSimplePEMP256SEC1PrivateKey() throws {
        let pemPrivateKey = """
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIHwS3r7tdBfDPSOaT/x6A2qvXFFXlGmnaYkxzrj1CQUHoAoGCCqGSM49
    AwEHoUQDQgAE79HvsMQC9IyhZ7yCCYKmgz9zewM4KziWoVMXKN+7Cd5Ds+jK8V5q
    hD6YVbbo/v1udmM5DfhHJiUW3Ww5++suRg==
    -----END EC PRIVATE KEY-----
    """
        
        // Test the working private keys.
        let signingKey = try orFail { try P256.Signing.PrivateKey(pemRepresentation: pemPrivateKey) }
        let keyAgreementKey = try orFail { try P256.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)
        
        // Now the non-matching private keys.
        XCTAssertThrowsError(try P384.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P521.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))
        
        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P384.Signing.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P521.Signing.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)

        // We can't reserialize the SEC1 keys, we don't emit them.
    }
    
    func testSimplePEMP384SEC1PrivateKey() throws {
        let pemPrivateKey = """
    -----BEGIN EC PRIVATE KEY-----
    MIGkAgEBBDDrN+qjvW7TqcXrKlTFbSP8AdbsIdqvRAgWHlaBicP7dkx+HKQidSiS
    B2RLWyjSrs6gBwYFK4EEACKhZANiAAQrRiaztGpInYo1XqMnNokWY6g1TcgMuzgq
    Ug6LzFQbCAqCrcnM9+c9Z4/63dC06ulL/KbLQgThjSiqRzgbzvmOvB0OzlpX1weK
    usFrF4Pi0B9pKPmVCAlSzaxVEmRsbmw=
    -----END EC PRIVATE KEY-----
    """
        
        // Test the working private keys.
        let signingKey = try orFail { try P384.Signing.PrivateKey(pemRepresentation: pemPrivateKey) }
        let keyAgreementKey = try orFail { try P384.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)
        
        // Now the non-matching private keys.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P521.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))
        
        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P384.Signing.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P521.Signing.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)

        // We can't reserialize the SEC1 keys, we don't emit them.
    }
    
    func testSimplePEMP521SEC1PrivateKey() throws {
        let pemPrivateKey = """
    -----BEGIN EC PRIVATE KEY-----
    MIHcAgEBBEIBf4tGkyicrFEadZv7iWnmCGsDk7S18CTCUD7n4+XOG6GbVNLwpBsE
    naUP5eXHm5Bxuiir0BIsKATXx0ZwEjULpfCgBwYFK4EEACOhgYkDgYYABAEiHfCR
    mQtxxjthsfQ987aSYGgxcCLxBaj8/fW4U7jufPcqxz27x9wi1qB2rZmOKaSsh1JZ
    wF5yOAMX4/acIK1OdgGzbafukRZjqF3wKVP8UFH0DzdNaZ8aSplgUu8gV2TjJyQB
    1sCKaVuecBtTRiIwvnapv5PgQIgstPQmRhqVOLriDA==
    -----END EC PRIVATE KEY-----
    """
        
        // Test the working private keys.
        let signingKey = try orFail { try P521.Signing.PrivateKey(pemRepresentation: pemPrivateKey) }
        let keyAgreementKey = try orFail { try P521.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)
        
        // Now the non-matching private keys.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P384.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))
        
        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P384.Signing.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P521.Signing.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey),
                             error: CryptoKitASN1Error.invalidPEMDocument)

        // We can't reserialize the SEC1 keys, we don't emit them.
    }
    
    func testSimpleDERP256SPKI() throws {
        let b64PublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIq+Qd2HviOb1JAkvKInCCec/gbZRnEZ6H9gO29wJ1H/a8Mmmog7b8nj+xEgo7Rh5dKlNgRaKvVjlLDllq+bPAA=="
        let derPublicKey = Data(base64Encoded: b64PublicKey)!
        
        // Test the working public keys.
        let signingKey = try orFail { try P256.Signing.PublicKey(derRepresentation: derPublicKey) }
        let keyAgreementKey = try orFail { try P256.KeyAgreement.PublicKey(derRepresentation: derPublicKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)
        
        // Now the non-matching public keys.
        XCTAssertThrowsError(try P384.Signing.PublicKey(derRepresentation: derPublicKey),
                             error: CryptoKitError.incorrectParameterSize)
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(derRepresentation: derPublicKey),
                             error: CryptoKitError.incorrectParameterSize)
        XCTAssertThrowsError(try P521.Signing.PublicKey(derRepresentation: derPublicKey),
                             error: CryptoKitError.incorrectParameterSize)
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(derRepresentation: derPublicKey),
                             error: CryptoKitError.incorrectParameterSize)

        // Now the private keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(derRepresentation: derPublicKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(derRepresentation: derPublicKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P384.Signing.PrivateKey(derRepresentation: derPublicKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(derRepresentation: derPublicKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P521.Signing.PrivateKey(derRepresentation: derPublicKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(derRepresentation: derPublicKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)

        // Validate we can reserialize.
        let firstReserialization = signingKey.derRepresentation
        let secondReserialization = keyAgreementKey.derRepresentation
        XCTAssertEqual(firstReserialization, derPublicKey)
        XCTAssertEqual(secondReserialization, derPublicKey)
    }
    
    func testSimpleDERP384SPKI() throws {
        let b64PublicKey = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEvt9xABn4WAo0EQsp3BMEd26f3qrXJ5RrhU1i2wp0G29oK2cdNareBirnyjlsQEg/OQ+ZQyKmMrxm5OrbhvJf/+97dc6phzb2R/blH62I65BiUSBAsGaXU69ObTPOwDKT"
        let derPublicKey = Data(base64Encoded: b64PublicKey)!
        
        // Test the working public keys.
        let signingKey = try orFail { try P384.Signing.PublicKey(derRepresentation: derPublicKey) }
        let keyAgreementKey = try orFail { try P384.KeyAgreement.PublicKey(derRepresentation: derPublicKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)
        
        // Now the non-matching public keys.
        XCTAssertThrowsError(try P256.Signing.PublicKey(derRepresentation: derPublicKey),
                             error: CryptoKitError.incorrectParameterSize)
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(derRepresentation: derPublicKey),
                             error: CryptoKitError.incorrectParameterSize)
        XCTAssertThrowsError(try P521.Signing.PublicKey(derRepresentation: derPublicKey),
                             error: CryptoKitError.incorrectParameterSize)
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(derRepresentation: derPublicKey),
                             error: CryptoKitError.incorrectParameterSize)

        // Now the private keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(derRepresentation: derPublicKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(derRepresentation: derPublicKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P384.Signing.PrivateKey(derRepresentation: derPublicKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(derRepresentation: derPublicKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P521.Signing.PrivateKey(derRepresentation: derPublicKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(derRepresentation: derPublicKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)

        // Validate we can reserialize.
        let firstReserialization = signingKey.derRepresentation
        let secondReserialization = keyAgreementKey.derRepresentation
        XCTAssertEqual(firstReserialization, derPublicKey)
        XCTAssertEqual(secondReserialization, derPublicKey)
    }
    
    func testSimpleDERP521SPKI() throws {
        let b64PublicKey = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAfH9fsVM7MdTe88+kvkZmFq9nPLMAPvCyAf5PYnJ7qV3W0rtVC2R3c0Aw21QxeN4XAIFcElO9NQ+ErT/m4o6+1YgBlLfBTnHKTq/WTNjQWxQk8i1PzHMsplT41OMAm0LaHwi9s+mWUIGlbfcP+MmVKY5dMkskPsU2YBlLZI81xk+z2X4="
        let derPublicKey = Data(base64Encoded: b64PublicKey)!
        
        // Test the working public keys.
        let signingKey = try orFail { try P521.Signing.PublicKey(derRepresentation: derPublicKey) }
        let keyAgreementKey = try orFail { try P521.KeyAgreement.PublicKey(derRepresentation: derPublicKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)
        
        // Now the non-matching public keys.
        XCTAssertThrowsError(try P256.Signing.PublicKey(derRepresentation: derPublicKey),
                             error: CryptoKitError.incorrectParameterSize)
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(derRepresentation: derPublicKey),
                             error: CryptoKitError.incorrectParameterSize)
        XCTAssertThrowsError(try P384.Signing.PublicKey(derRepresentation: derPublicKey),
                             error: CryptoKitError.incorrectParameterSize)
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(derRepresentation: derPublicKey),
                             error: CryptoKitError.incorrectParameterSize)

        // Now the private keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(derRepresentation: derPublicKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(derRepresentation: derPublicKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P384.Signing.PrivateKey(derRepresentation: derPublicKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(derRepresentation: derPublicKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P521.Signing.PrivateKey(derRepresentation: derPublicKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(derRepresentation: derPublicKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)

        // Validate we can reserialize.
        let firstReserialization = signingKey.derRepresentation
        let secondReserialization = keyAgreementKey.derRepresentation
        XCTAssertEqual(firstReserialization, derPublicKey)
        XCTAssertEqual(secondReserialization, derPublicKey)
    }
    
    func testSimpleDERP256PKCS8() throws {
        let b64PrivateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgxWaWfbbhHsTjtEwkANo6ZDeJ2CARYhjOSt2auAW7xNOhRANCAAQsAL3hTMCCbh1kVCSJa8V22WLNDriEpVOLEJXiVFEwAFjWd1BufewuT69tYa0hyB1Q3pt12HPK2c1KGwjOpScW"
        let derPrivateKey = Data(base64Encoded: b64PrivateKey)!
        
        // Test the working private keys.
        let signingKey = try orFail { try P256.Signing.PrivateKey(derRepresentation: derPrivateKey) }
        let keyAgreementKey = try orFail { try P256.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)
        
        // Now the non-matching private keys.
        XCTAssertThrowsError(try P384.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P521.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))
        
        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P384.Signing.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P521.Signing.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)

        // Validate we can reserialize.
        let firstReserialization = signingKey.derRepresentation
        let secondReserialization = keyAgreementKey.derRepresentation
        XCTAssertEqual(firstReserialization, derPrivateKey)
        XCTAssertEqual(secondReserialization, derPrivateKey)
    }
    
    func testSimpleDERP384PKCS8() throws {
        let b64PrivateKey = "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAsdACCJGneotN0y5zQjZxImZuH3TuvHeKWXKi2m6d3fYsGOufibIqaxfCLVZGvxb2hZANiAARL6IhECKbw5UCSqGaaZ3H5FNbXuk/4y4QTJLhdQRBkibr6YjEzFGDgd1yjU0msBOMBvx3oCZ5rPgVaogQXPdZbx8PnTt2I+2x2BuoRibA+/yCAyJSluVm/005p0EcAmuI="
        let derPrivateKey = Data(base64Encoded: b64PrivateKey)!
        
        // Test the working private keys.
        let signingKey = try orFail { try P384.Signing.PrivateKey(derRepresentation: derPrivateKey) }
        let keyAgreementKey = try orFail { try P384.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)
        
        // Now the non-matching private keys.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P521.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))
        
        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P384.Signing.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P521.Signing.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)

        // Validate we can reserialize.
        let firstReserialization = signingKey.derRepresentation
        let secondReserialization = keyAgreementKey.derRepresentation
        XCTAssertEqual(firstReserialization, derPrivateKey)
        XCTAssertEqual(secondReserialization, derPrivateKey)
    }
    
    func testSimpleDERP521PKCS8() throws {
        let b64PrivateKey = "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIA2u5+KHPk/vVrYI53Khh3WrFmxUCQ5YeK6HAi+GyebeRM3w1KoQuD4oHocp2aKffjjWKVkEfLRfjraJgh1jH+GPihgYkDgYYABAC4M0cSEZ+hKwn65PQtdFu+L1ZdBt4kjrGJ2ggNG+tQ3z4S11KV9b+R+CyUajajhU2nJ4UkHQO5bEaTPmaWySFSVQEZilLlYtnQZSKGLS2DR4zBsny0O2+D5DpFSYKsDPN23MdOBdTam2Gqtm/WAirVmXMqs8v5VSjmh3i/EG6EDPEtXw=="
        let derPrivateKey = Data(base64Encoded: b64PrivateKey)!
        
        // Test the working private keys.
        let signingKey = try orFail { try P521.Signing.PrivateKey(derRepresentation: derPrivateKey) }
        let keyAgreementKey = try orFail { try P521.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)
        
        // Now the non-matching private keys.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P384.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))
        
        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P384.Signing.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P521.Signing.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)

        // Validate we can reserialize.
        let firstReserialization = signingKey.derRepresentation
        let secondReserialization = keyAgreementKey.derRepresentation
        XCTAssertEqual(firstReserialization, derPrivateKey)
        XCTAssertEqual(secondReserialization, derPrivateKey)
    }
    
    func testSimpleDERP256SEC1PrivateKey() throws {
        let b64PrivateKey = "MHcCAQEEIKzmkxtADyr8LymuVMqpLFVlx27bdgT0+un4I2a3DE1KoAoGCCqGSM49AwEHoUQDQgAEZp2q8QP4shIBZIHS1b1ZBUeLbrpnTA6CB17iFzF8udyYmcRkDAPSBamFXf4IthinYkfnru/PymZl+tpeM56BOw=="
        let derPrivateKey = Data(base64Encoded: b64PrivateKey)!
        
        // Test the working private keys.
        let signingKey = try orFail { try P256.Signing.PrivateKey(derRepresentation: derPrivateKey) }
        let keyAgreementKey = try orFail { try P256.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)
        
        // Now the non-matching private keys.
        XCTAssertThrowsError(try P384.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P521.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))
        
        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P384.Signing.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P521.Signing.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)

        // We can't reserialize the SEC1 keys, we don't emit them.
    }
    
    func testSimpleDERP384SEC1PrivateKey() throws {
        let b64PrivateKey = "MIGkAgEBBDAF5FSBF7Se55zRtIyMRcKgFWAEx0ixHqeevUFerPVtvZC7U2LfGOx9GMR5V+Nj7uagBwYFK4EEACKhZANiAAQCXRQ9B+RYv6zvQVdP2xZ0/8U3nzcOdWuAMb0BvjqkE/xDhHp7DYNGEv4pWhj1hkl9Tv5jum0eqAGgzq1hLpeY2aWnwk8fqnrDVDcnWrZe/9QpmHGaOP1YJXuyaJRnBWo="
        let derPrivateKey = Data(base64Encoded: b64PrivateKey)!
        
        // Test the working private keys.
        let signingKey = try orFail { try P384.Signing.PrivateKey(derRepresentation: derPrivateKey) }
        let keyAgreementKey = try orFail { try P384.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)
        
        // Now the non-matching private keys.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P521.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))
        
        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P384.Signing.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P521.Signing.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)

        // We can't reserialize the SEC1 keys, we don't emit them.
    }
    
    func testSimpleDERP521SEC1PrivateKey() throws {
        let b64PrivateKey = "MIHcAgEBBEIBFQwJ2Spw90Sn7oOnBKU6ob5Zoq9qBo6YiarvTok4jurO2VSQTyrmk02KK8EmZ/ZQqXRl/mZm0hLXwKBdUe+MPfSgBwYFK4EEACOhgYkDgYYABAEFYqZABFf2NBxxLb7rUV/pKAO8IF/ddIs2BY9dU/Ru6sQBOT6lzr5pGZC4a0o30ZGWNOvMq503Ev7/XDjW8fdPCQBGm4JGOOI/Pr008wsASEQOvloAUEQ+HOTZ94Dk3OTHqqahtgjp2BLGvMWHf1PwMsXv98nLE+LEYTQ8fzTgbUJwxg=="
        let derPrivateKey = Data(base64Encoded: b64PrivateKey)!
        
        // Test the working private keys.
        let signingKey = try orFail { try P521.Signing.PrivateKey(derRepresentation: derPrivateKey) }
        let keyAgreementKey = try orFail { try P521.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)
        
        // Now the non-matching private keys.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P384.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))
        
        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P384.Signing.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P521.Signing.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(derRepresentation: derPrivateKey),
                             error: CryptoKitASN1Error.unexpectedFieldType)

        // We can't reserialize the SEC1 keys, we don't emit them.
    }
    
    func testInvalidPEMP521PKCS8() throws {
        // This key is generated by an older OpenSSL or LibreSSL, which forgets to zero-pad the
        // private key. We want to validate that we correctly reject this.
        let pemPrivateKey = """
    -----BEGIN PRIVATE KEY-----
    MIHtAgEAMBAGByqGSM49AgEGBSuBBAAjBIHVMIHSAgEBBEFtmqAvS3jccVAam+Yn
    y3iiwMi6q8roJeAtxqdOkZUCdZ3Rf6lD0nehiH4QN7xOrhHrAIeZWe0ld2XUawGF
    H0ltO6GBiQOBhgAEAJHKKLTdXvL1DyZX4TI0kEi63I9cwtg09CQZ/Bp+K9MWsx9S
    bjIEBcr3yEKlUmRW+TKNoXo50ycbl4DlLknN2VbGAXE22e2sz8RQ1omvDE6lLBvB
    A5UvlNrk6ioTg2tumXD3Co06r1Hn+7lkkcjfT5mZO4jy7vP9ItvprJrIa6ySzVQ8
    -----END PRIVATE KEY-----
    """
        
        // This is not a valid private key for P521.
        XCTAssertThrowsError(try P521.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))
    }
    
    func testInvalidDERP521PKCS8() throws {
        // This key is generated by an older OpenSSL or LibreSSL, which forgets to zero-pad the
        // private key. We want to validate that we correctly reject this.
        let b64PrivateKey = "MIHtAgEAMBAGByqGSM49AgEGBSuBBAAjBIHVMIHSAgEBBEG1erZ/O4JMc11uT3SLJPQ4ICWbEdM0e8d1mI/uUhbZ6nE90jq38FZYkvKf6q3d1DUWJj8aWjktq2+gfCSD+XFulaGBiQOBhgAEAYKbRHQpjqaS17SwXAQzpUct9i+TyVUdDtQVpwxVTVhuklvTEWqypvSAyhqo9nPf/aKHl4fQD94Fd3RTzOmW8x+nAGnWGO6ZG1OQ72NCmT9fyB8dG2ifeDpICKuEq6reVIBDSQvi5F98C/lEIgu2r+MGYWj+S7pjEmSqksSjsJ3Oxo9U"
        let derPrivateKey = Data(base64Encoded: b64PrivateKey)!
        
        // This is not a valid private key for P521.
        XCTAssertThrowsError(try P521.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))
    }

    func testRejectX963CompressedRepresentation() throws {
        let privateKey = P256.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        
        try XCTAssertNoThrow(P256.KeyAgreement.PublicKey(x963Representation: publicKey.x963Representation))
        try XCTAssertThrowsError(P256.KeyAgreement.PublicKey(x963Representation: publicKey.compressedRepresentation),
                                 error: CryptoKitError.incorrectParameterSize)
    }
}
fileprivate extension Data {
    init?(base64urlEncoded input: String) {
        var base64 = input
        base64 = base64.replacingOccurrences(of: "-", with: "+")
        base64 = base64.replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 {
            base64 = base64.appending("=")
        }
        self.init(base64Encoded: base64)
    }
}

#endif // CRYPTO_IN_SWIFTPM
