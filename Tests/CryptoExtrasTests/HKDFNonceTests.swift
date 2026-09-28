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

        let nonce = try HKDF<SHA256>.deriveAESGCMNonce(
            inputKeyMaterial: ikm,
            salt: salt,
            info: info
        )

        // Verify nonce is exactly 12 bytes
        var byteCount = 0
        nonce.withUnsafeBytes { byteCount = $0.count }
        XCTAssertEqual(byteCount, 12)

        // Verify repeatability with same inputs
        let nonce2 = try HKDF<SHA256>.deriveAESGCMNonce(
            inputKeyMaterial: ikm,
            salt: salt,
            info: info
        )
        let bytes1 = nonce.withUnsafeBytes { Data($0) }
        let bytes2 = nonce2.withUnsafeBytes { Data($0) }
        XCTAssertEqual(bytes1, bytes2)

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

        let nonce = try HKDF<SHA256>.deriveChaChaPolyNonce(
            inputKeyMaterial: ikm,
            salt: salt,
            info: info
        )

        var byteCount = 0
        nonce.withUnsafeBytes { byteCount = $0.count }
        XCTAssertEqual(byteCount, 12)

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

        let nonceAlice = try sharedSecretAlice.hkdfDerivedAESGCMNonce(
            using: SHA256.self,
            salt: salt,
            sharedInfo: info
        )
        let nonceBob = try sharedSecretBob.hkdfDerivedAESGCMNonce(
            using: SHA256.self,
            salt: salt,
            sharedInfo: info
        )

        let bytesAlice = nonceAlice.withUnsafeBytes { Data($0) }
        let bytesBob = nonceBob.withUnsafeBytes { Data($0) }
        XCTAssertEqual(bytesAlice, bytesBob)

        let chaChaAlice = try sharedSecretAlice.hkdfDerivedChaChaPolyNonce(
            using: SHA256.self,
            salt: salt,
            sharedInfo: info
        )
        let chaChaBob = try sharedSecretBob.hkdfDerivedChaChaPolyNonce(
            using: SHA256.self,
            salt: salt,
            sharedInfo: info
        )
        let chaChaBytesAlice = chaChaAlice.withUnsafeBytes { Data($0) }
        let chaChaBytesBob = chaChaBob.withUnsafeBytes { Data($0) }
        XCTAssertEqual(chaChaBytesAlice, chaChaBytesBob)
    }
}
