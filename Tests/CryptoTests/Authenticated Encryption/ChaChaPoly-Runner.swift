//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
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
import Crypto
#elseif (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
import CryptoKit
#else
import Crypto
#endif

class ChaChaPolyTests: XCTestCase {
    func testIncorrectKeySize() throws {
        let plaintext: Data = "Some Super Secret Message".data(using: String.Encoding.utf8)!

        let wrongKey = SymmetricKey(size: .bits128)
        let key = SymmetricKey(size: .bits256)
        let nonce = ChaChaPoly.Nonce()

        XCTAssertThrowsError(try ChaChaPoly.seal(plaintext, using: wrongKey, nonce: nonce))
        let message = try orFail { try ChaChaPoly.seal(plaintext, using: key, nonce: nonce) }

        XCTAssertThrowsError(try ChaChaPoly.open(message, using: wrongKey))
        XCTAssertNoThrow(try ChaChaPoly.open(message, using: key))
    }

    func testExtractingBytesFromNonce() throws {
        let nonce = ChaChaPoly.Nonce()
        XCTAssertEqual(Array(nonce), nonce.withUnsafeBytes { Array($0) })

        let testNonceBytes = Array(UInt8(0)..<UInt8(12))
        let (contiguousNonceBytes, discontiguousNonceBytes) = testNonceBytes.asDataProtocols()
        let nonceFromContiguous = try orFail { try ChaChaPoly.Nonce(data: contiguousNonceBytes) }
        let nonceFromDiscontiguous = try orFail { try ChaChaPoly.Nonce(data: discontiguousNonceBytes) }

        XCTAssertEqual(Array(nonceFromContiguous), testNonceBytes)
        XCTAssertEqual(Array(nonceFromDiscontiguous), testNonceBytes)

        XCTAssertThrowsError(try ChaChaPoly.Nonce(data: DispatchData.empty)) { error in
            guard case .some(.incorrectParameterSize) = error as? CryptoKitError else {
                XCTFail("Unexpected error")
                return
            }
        }
    }

    func testEncryptDecrypt() throws {
        let plaintext: Data = "Some Super Secret Message".data(using: String.Encoding.utf8)!

        let key = SymmetricKey(size: .bits256)
        let nonce = ChaChaPoly.Nonce()

        let ciphertext = try orFail { try ChaChaPoly.seal(plaintext, using: key, nonce: nonce, authenticating: Data()) }
        let recoveredPlaintext = try orFail { try ChaChaPoly.open(ciphertext, using: key, authenticating: Data()) }

        XCTAssertEqual(recoveredPlaintext, plaintext)
    }

    func testUserConstructedSealedBoxesCombined() throws {
        let ciphertext = Array("This pretty clearly isn't ciphertext, but sure why not".utf8)
        let (contiguousCiphertext, discontiguousCiphertext) = ciphertext.asDataProtocols()

        let contiguousSB = try orFail { try ChaChaPoly.SealedBox(combined: contiguousCiphertext) }
        let discontiguousSB = try orFail { try ChaChaPoly.SealedBox(combined: discontiguousCiphertext) }
        XCTAssertEqual(contiguousSB.combined, discontiguousSB.combined)
        XCTAssertEqual(Array(contiguousSB.nonce), Array(discontiguousSB.nonce))
        XCTAssertEqual(contiguousSB.ciphertext, discontiguousSB.ciphertext)
        XCTAssertEqual(contiguousSB.tag, discontiguousSB.tag)

        // Empty dispatchdatas don't work, they are too small.
        XCTAssertThrowsError(try ChaChaPoly.SealedBox(combined: DispatchData.empty)) { error in
            guard case .some(.incorrectParameterSize) = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
    }

    func testUserConstructedSealedBoxesSplit() throws {
        let tag = Array(repeating: UInt8(0), count: 16)
        let ciphertext = Array("This pretty clearly isn't ciphertext, but sure why not".utf8)
        let nonce = ChaChaPoly.Nonce()

        let (contiguousCiphertext, discontiguousCiphertext) = ciphertext.asDataProtocols()
        let (contiguousTag, discontiguousTag) = tag.asDataProtocols()

        // Two separate data protocol inputs means we end up with 4 boxes.
        let contiguousContiguous = try orFail {
            try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: contiguousCiphertext, tag: contiguousTag)
        }
        let discontiguousContiguous = try orFail {
            try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: discontiguousCiphertext, tag: contiguousTag)
        }
        let contiguousDiscontiguous = try orFail {
            try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: contiguousCiphertext, tag: discontiguousTag)
        }
        let discontiguousDiscontiguous = try orFail {
            try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: discontiguousCiphertext, tag: discontiguousTag)
        }

        // To avoid the comparison count getting too nuts, we use the combined representation. By the transitive
        // property we only need three comparisons.
        XCTAssertEqual(contiguousContiguous.combined, discontiguousContiguous.combined)
        XCTAssertEqual(discontiguousContiguous.combined, contiguousDiscontiguous.combined)
        XCTAssertEqual(contiguousDiscontiguous.combined, discontiguousDiscontiguous.combined)

        // Empty dispatchdatas for the tag don't work, they are too small.
        XCTAssertThrowsError(try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: DispatchData.empty)) { error in
            guard case .some(.incorrectParameterSize) = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }

        // They work fine for the ciphertext though.
        let weirdBox = try orFail { try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: DispatchData.empty, tag: tag) }
        XCTAssertEqual(weirdBox.ciphertext, Data())
    }

    func testRoundTripDataProtocols() throws {
        func roundTrip<Message: DataProtocol, AAD: DataProtocol>(message: Message, aad: AAD, file: StaticString = (#file), line: UInt = #line) throws {
            let key = SymmetricKey(size: .bits256)
            let nonce = ChaChaPoly.Nonce()

            let ciphertext = try orFail(file: file, line: line) { try ChaChaPoly.seal(message, using: key, nonce: nonce, authenticating: aad) }
            let recoveredPlaintext = try orFail(file: file, line: line) { try ChaChaPoly.open(ciphertext, using: key, authenticating: aad) }

            XCTAssertEqual(Array(recoveredPlaintext), Array(message), file: file, line: line)
        }

        let message = Array("Hello, world, it's ChaCha!".utf8)
        let aad = Array("ChaChaChaCha".utf8)
        let (contiguousMessage, discontiguousMessage) = message.asDataProtocols()
        let (contiguousAad, discontiguousAad) = aad.asDataProtocols()

        _ = try orFail { try roundTrip(message: contiguousMessage, aad: contiguousAad) }
        _ = try orFail { try roundTrip(message: discontiguousMessage, aad: contiguousAad) }
        _ = try orFail { try roundTrip(message: contiguousMessage, aad: discontiguousAad) }
        _ = try orFail { try roundTrip(message: discontiguousMessage, aad: discontiguousAad) }
    }

    func testWycheproof() throws {
        try orFail {
            try wycheproofTest(
                bundleType: self,
                jsonName: "chacha20_poly1305_test",
                testFunction: { (group: AEADTestGroup) in
                    _ = try orFail { try testGroup(group: group) }
                })
        }
    }

    func testGroup(group: AEADTestGroup) throws {
        for testVector in group.tests {
            var msg: Data = Data()
            var aad: Data = Data()
            var ct: [UInt8] = []
            var tag: [UInt8] = []

            var nonce: ChaChaPoly.Nonce

            do {
                nonce = try ChaChaPoly.Nonce(data: Array(hexString: testVector.iv))
            } catch {
                XCTAssertEqual(testVector.result, "invalid")
                return
            }

            if testVector.ct.count > 0 {
                ct = try orFail { try Array(hexString: testVector.ct) }
            }

            if testVector.msg.count > 0 {
                msg = try orFail { try Data(hexString: testVector.msg) }
            }

            if testVector.aad.count > 0 {
                aad = try orFail { try Data(hexString: testVector.aad) }
            }

            if testVector.tag.count > 0 {
                tag = try orFail { try Array(hexString: testVector.tag) }
            }

            let key = try orFail { try SymmetricKey(data: Array(hexString: testVector.key)) }
            XCTAssertNotNil(key)

            let sb = try orFail { try ChaChaPoly.seal(msg, using: key, nonce: nonce, authenticating: aad) }

            XCTAssertEqual(Data(ct), sb.ciphertext)

            if testVector.result == "valid" {
                XCTAssertEqual(Data(tag), sb.tag)
            }

            do {
                let recovered_pt = try ChaChaPoly.open(ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ct, tag: tag), using: key, authenticating: aad)

                if testVector.result == "valid" || testVector.result == "acceptable" {
                    XCTAssertEqual(recovered_pt, msg)
                }
            } catch {
                XCTAssertEqual(testVector.result, "invalid")
            }
        }
    }
}
