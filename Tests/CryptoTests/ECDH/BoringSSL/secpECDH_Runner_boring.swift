//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
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

#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// Skip tests that require @testable imports of CryptoKit.
#else
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@testable import CryptoKit
#else
@_implementationOnly import CCryptoBoringSSL
@testable import Crypto
#endif

extension NISTECDHTests {
    func testGroupOpenSSL<PrivKey: NISTECPrivateKey & DiffieHellmanKeyAgreement, Curve: OpenSSLSupportedNISTCurve>(group: ECDHTestGroup, privateKeys: PrivKey.Type, onCurve curve: Curve.Type) {
        func padKeyIfNecessary(vector: String, curveDetails: OpenSSLSupportedNISTCurve.Type) -> [UInt8] {
            let hexStringFromVector = (vector.count % 2 == 0) ? vector : "0\(vector)"
            return try! Array(hexString: hexStringFromVector)
        }

        for testVector in group.tests {
            do {
                let pkBytes = try Array(hexString: testVector.publicKey)
                let publicKey = try PrivKey.PublicKey(derBytes: pkBytes, curve: Curve.self)

                var privateBytes = [UInt8]()
                privateBytes = padKeyIfNecessary(vector: testVector.privateKey, curveDetails: curve)

                let privateKey = try PrivKey(rawRepresentation: privateBytes)

                let result = try privateKey.sharedSecretFromKeyAgreement(with: publicKey as! PrivKey.P)

                let expectedResult = try Array(hexString: testVector.shared)

                XCTAssertEqual(Array(result.ss), Array(expectedResult))
            } catch ECDHTestErrors.PublicKeyFailure {
                XCTAssert(testVector.flags.contains("CompressedPoint") || testVector.result == "invalid" || testVector.flags.contains("InvalidPublic") || testVector.flags.contains("InvalidAsn"))
            } catch ECDHTestErrors.ParseSPKIFailure {
                XCTAssert(testVector.flags.contains("InvalidAsn") || testVector.flags.contains("UnnamedCurve"))
            } catch {
                if testVector.result == "valid" {
                    XCTAssert(testVector.tcId == 31 || testVector.tcId == 20 || testVector.tcId == 25)
                }
            }
        }
    }
}

extension NISTECPublicKey {
    /// Creates the given EC public key using the DER encoding of the key.
    init<Curve: OpenSSLSupportedNISTCurve>(derBytes: [UInt8], curve: Curve.Type = Curve.self) throws {
        // Bad news everybody. Using the EC DER parsing from OpenSSL limits our ability to tell the difference
        // between an invalid SPKI layout (which we don't care about, as the production library doesn't support DER-encoded
        // EC keys) and a SPKI layout that is syntactically valid but doesn't represent a valid point on the curve. We _do_
        // care about passing this into the production library.
        //
        // This means we've only one option: we have to implement "just enough" ASN.1.
        var derBytes = derBytes[...]
        let spki = try ASN1SubjectPublicKeyInfo(fromASN1: &derBytes)
        guard derBytes.count == 0, spki.algorithm.algorithm == ASN1ObjectIdentifier.AlgorithmIdentifier.idEcPublicKey else {
            throw ECDHTestErrors.ParseSPKIFailure
        }

        // Ok, the bitstring we are holding is the X963 representation of the public key. Try to create it.
        do {
            try self.init(x963Representation: spki.subjectPublicKey)
        } catch {
            throw ECDHTestErrors.PublicKeyFailure
        }
    }
}

#endif // (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM
