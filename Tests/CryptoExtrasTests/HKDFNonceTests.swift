//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import XCTest

@testable import CryptoExtras

@available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
final class HKDFNonceTests: XCTestCase {
    func testHKDFDeriveAESGCMNonce() throws {
        let ikm = SymmetricKey(size: .bits256)
        let salt = "test-salt".data(using: .utf8)!
        let info = "test-info".data(using: .utf8)!

        let nonce = try HKDF<SHA256>._deriveAESGCMNonce(
            inputKeyMaterial: ikm,
            salt: salt,
            info: info,
            sequenceNumber: 0
        )

        // Verify nonce is exactly 12 bytes
        var byteCount = 0
        nonce.withUnsafeBytes { byteCount = $0.count }
        XCTAssertEqual(byteCount, 12)

        // Verify repeatability with same inputs and sequence number
        let nonce2 = try HKDF<SHA256>._deriveAESGCMNonce(
            inputKeyMaterial: ikm,
            salt: salt,
            info: info,
            sequenceNumber: 0
        )
        let bytes1 = nonce.withUnsafeBytes { Data($0) }
        let bytes2 = nonce2.withUnsafeBytes { Data($0) }
        XCTAssertEqual(bytes1, bytes2)

        // Verify different sequence numbers yield different nonces (nonce uniqueness)
        let nonceSeq1 = try HKDF<SHA256>._deriveAESGCMNonce(
            inputKeyMaterial: ikm,
            salt: salt,
            info: info,
            sequenceNumber: 1
        )
        let bytesSeq1 = nonceSeq1.withUnsafeBytes { Data($0) }
        XCTAssertNotEqual(bytes1, bytesSeq1)

        // Verify domain separation: a 32-byte key derived with the exact same PRK and info
        // does NOT have its first 12 bytes match the derived nonce
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: salt,
            info: info,
            outputByteCount: 32
        )
        let keyFirst12Bytes = derivedKey.withUnsafeBytes { Data($0.prefix(12)) }
        XCTAssertNotEqual(bytes1, keyFirst12Bytes, "Domain separation must prevent key prefix leakage")

        // Verify seal works with derived nonce
        let message = "Secret Message".data(using: .utf8)!
        let key = SymmetricKey(size: .bits256)
        let sealed = try AES.GCM.seal(message, using: key, nonce: nonce)
        let opened = try AES.GCM.open(sealed, using: key)
        XCTAssertEqual(opened, message)
    }

    func testHKDFDeriveChaChaPolyNonce() throws {
        let ikm = SymmetricKey(size: .bits256)
        let salt = "test-salt".data(using: .utf8)!
        let info = "test-info".data(using: .utf8)!

        let nonce = try HKDF<SHA256>._deriveChaChaPolyNonce(
            inputKeyMaterial: ikm,
            salt: salt,
            info: info,
            sequenceNumber: 0
        )

        var byteCount = 0
        nonce.withUnsafeBytes { byteCount = $0.count }
        XCTAssertEqual(byteCount, 12)

        // Verify different sequence numbers yield different nonces
        let nonceSeq1 = try HKDF<SHA256>._deriveChaChaPolyNonce(
            inputKeyMaterial: ikm,
            salt: salt,
            info: info,
            sequenceNumber: 1
        )
        let bytes0 = nonce.withUnsafeBytes { Data($0) }
        let bytes1 = nonceSeq1.withUnsafeBytes { Data($0) }
        XCTAssertNotEqual(bytes0, bytes1)

        // Verify seal works with derived nonce
        let message = "Secret Message".data(using: .utf8)!
        let key = SymmetricKey(size: .bits256)
        let sealed = try ChaChaPoly.seal(message, using: key, nonce: nonce)
        let opened = try ChaChaPoly.open(sealed, using: key)
        XCTAssertEqual(opened, message)
    }

    func testSharedSecretDeriveNonce() throws {
        let alicePrivateKey = P256.KeyAgreement.PrivateKey()
        let bobPrivateKey = P256.KeyAgreement.PrivateKey()

        let sharedSecretAlice = try alicePrivateKey.sharedSecretFromKeyAgreement(with: bobPrivateKey.publicKey)
        let sharedSecretBob = try bobPrivateKey.sharedSecretFromKeyAgreement(with: alicePrivateKey.publicKey)

        let salt = "ecdh-salt".data(using: .utf8)!
        let info = "ecdh-nonce-info".data(using: .utf8)!

        let nonceAlice = try sharedSecretAlice._hkdfDerivedAESGCMNonce(
            using: SHA256.self,
            salt: salt,
            sharedInfo: info,
            sequenceNumber: 0
        )
        let nonceBob = try sharedSecretBob._hkdfDerivedAESGCMNonce(
            using: SHA256.self,
            salt: salt,
            sharedInfo: info,
            sequenceNumber: 0
        )

        let bytesAlice = nonceAlice.withUnsafeBytes { Data($0) }
        let bytesBob = nonceBob.withUnsafeBytes { Data($0) }
        XCTAssertEqual(bytesAlice, bytesBob)

        // Verify sequence number uniqueness on SharedSecret
        let nonceAliceSeq1 = try sharedSecretAlice._hkdfDerivedAESGCMNonce(
            using: SHA256.self,
            salt: salt,
            sharedInfo: info,
            sequenceNumber: 1
        )
        let bytesAliceSeq1 = nonceAliceSeq1.withUnsafeBytes { Data($0) }
        XCTAssertNotEqual(bytesAlice, bytesAliceSeq1)

        let chaChaAlice = try sharedSecretAlice._hkdfDerivedChaChaPolyNonce(
            using: SHA256.self,
            salt: salt,
            sharedInfo: info,
            sequenceNumber: 0
        )
        let chaChaBob = try sharedSecretBob._hkdfDerivedChaChaPolyNonce(
            using: SHA256.self,
            salt: salt,
            sharedInfo: info,
            sequenceNumber: 0
        )
        let chaChaBytesAlice = chaChaAlice.withUnsafeBytes { Data($0) }
        let chaChaBytesBob = chaChaBob.withUnsafeBytes { Data($0) }
        XCTAssertEqual(chaChaBytesAlice, chaChaBytesBob)
    }
}
