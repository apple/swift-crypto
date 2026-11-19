//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import XCTest

#if canImport(CryptoKit)
// Skip tests that require @testable imports of CryptoKit.
#else
@testable import Crypto

extension X25519Tests {
    func testKeyAgreementWithLowOrderPublicKeyThrows() throws {
        // The vectors whose shared secret is all-zero: the seven low-order u-coordinates, which are
        // 0, 1, both points of order 8, p-1, p and p+1, plus a non-canonical spelling of each.
        try wycheproofTest(
            bundleType: self,
            jsonName: "x25519_test",
            testFunction: { (group: ECDHTestGroup) in
                let zeroSharedSecretTests = group.tests.filter { $0.flags.contains("ZeroSharedSecret") }
                XCTAssert(!zeroSharedSecretTests.isEmpty)

                for testVector in zeroSharedSecretTests {
                    // The public key itself is accepted, as it is by CryptoKit; only the agreement fails.
                    let publicKey = try Curve25519.KeyAgreement.PublicKey(
                        rawRepresentation: Array(hexString: testVector.publicKey)
                    )
                    let privateKey = try Curve25519.KeyAgreement.PrivateKey(
                        rawRepresentation: Array(hexString: testVector.privateKey)
                    )
                    XCTAssertThrowsError(
                        try privateKey.sharedSecretFromKeyAgreement(with: publicKey),
                        "tcId \(testVector.tcId)"
                    )
                }
            }
        )
    }
}

#endif  // canImport(CryptoKit)
