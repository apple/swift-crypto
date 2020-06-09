//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
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
    func testGroupOpenSSL<PrivKey: NISTECPrivateKey & DiffieHellmanKeyAgreement, Curve: OpenSSLSupportedNISTCurve>(group: ECDHTestGroup, privateKeys: PrivKey.Type, onCurve curve: Curve.Type, file: StaticString = #file, line: UInt = #line) {
        func padKeyIfNecessary(vector: String, curveDetails: OpenSSLSupportedNISTCurve.Type, file: StaticString = #file, line: UInt = #line) throws -> [UInt8] {
            // There are a few edge cases here.
            //
            // First, our raw bytes function requires the
            // input buffer to be exactly as long as the curve size.
            //
            // Second, Wycheproof inputs may be too short or too long with
            // leading zeros.
            let curveSize = curve.coordinateByteCount
            var privateBytes = [UInt8](repeating: 0, count: curveSize)

            let hexStringFromVector = (vector.count % 2 == 0) ? vector : "0\(vector)"
            let privateKeyVector = try! Array(hexString: hexStringFromVector)

            // Input is too long (i.e. we have leading zeros)
            if privateKeyVector.count > curveSize {
                privateBytes = privateKeyVector.suffix(curveSize)
            } else if privateKeyVector.count == curveSize {
                privateBytes = privateKeyVector
            } else {
                // Input is too short
                privateBytes.replaceSubrange((privateBytes.count - privateKeyVector.count) ..< privateBytes.count, with: privateKeyVector)
            }

            return privateBytes
        }

        for testVector in group.tests {
            do {
                let pkBytes = try Array(hexString: testVector.publicKey)
                let publicKey = try PrivKey.PublicKey(derBytes: pkBytes, curve: Curve.self)

                var privateBytes = [UInt8]()
                privateBytes = try padKeyIfNecessary(vector: testVector.privateKey, curveDetails: curve)

                let privateKey = try PrivKey(rawRepresentation: privateBytes)

                let agreement = try unwrap(publicKey as? PrivKey.P, file: file, line: line)
                let result = try privateKey.sharedSecretFromKeyAgreement(with: agreement)

                let expectedResult = try Array(hexString: testVector.shared)

                XCTAssertEqual(Array(result.ss), Array(expectedResult), file: file, line: line)
            } catch ECDHTestErrors.PublicKeyFailure {
                XCTAssert(testVector.flags.contains("CompressedPoint") || testVector.result == "invalid" || testVector.flags.contains("InvalidPublic") || testVector.flags.contains("InvalidAsn"), file: file, line: line)
            } catch ECDHTestErrors.ParseSPKIFailure {
                XCTAssert(testVector.flags.contains("InvalidAsn") || testVector.flags.contains("UnnamedCurve"), file: file, line: line)
            } catch {
                if testVector.result == "valid" {
                    XCTAssert(testVector.tcId == 31 || testVector.tcId == 20 || testVector.tcId == 25, file: file, line: line)
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
