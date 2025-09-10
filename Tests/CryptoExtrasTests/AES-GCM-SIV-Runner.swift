//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCrypto project authors
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
import Crypto
import CryptoExtras

struct AEADTestGroup: Codable {
    let ivSize: Int
    let keySize: UInt16
    let tagSize: UInt16
    let type: String
    let tests: [AESGCMTestVector]
}

struct AESGCMTestVector: Codable {
    let key: String
    let iv: String
    let aad: String
    let msg: String
    let ct: String
    let tag: String
    let result: String
}

final class AESGCMSIVTests: XCTestCase {
    func testPropertiesStayTheSameAfterFailedOpening() throws {
        let message = Data("this is a message".utf8)
        let sealed = try AES.GCM._SIV.seal(message, using: SymmetricKey(size: .bits128))

        // We copy the bytes of these fields out here to ensure they're saved.
        let originalCiphertext = Array(sealed.ciphertext)
        let originalNonce = Array(sealed.nonce)
        let originalTag = Array(sealed.tag)

        XCTAssertThrowsError(try AES.GCM._SIV.open(sealed, using: SymmetricKey(size: .bits128)))

        // The fields must all be unchanged.
        XCTAssertEqual(originalCiphertext, Array(sealed.ciphertext))
        XCTAssertEqual(originalNonce, Array(sealed.nonce))
        XCTAssertEqual(originalTag, Array(sealed.tag))
    }

    func testBadKeySize() {
        let plaintext: Data = "Some Super Secret Message".data(using: String.Encoding.utf8)!
        let key = SymmetricKey(size: .init(bitCount: 304))
        let nonce = AES.GCM._SIV.Nonce()

        XCTAssertThrowsError(try AES.GCM._SIV.seal(plaintext, using: key, nonce: nonce))
    }

    func testEncryptDecrypt() throws {
        let plaintext: Data = "Some Super Secret Message".data(using: String.Encoding.utf8)!

        let key = SymmetricKey(size: .bits256)
        let nonce = AES.GCM._SIV.Nonce()

        let ciphertext = try AES.GCM._SIV.seal(plaintext, using: key, nonce: nonce)
        let recoveredPlaintext = try AES.GCM._SIV.open(ciphertext, using: key, authenticating: Data())
        let recoveredPlaintextWithoutAAD = try AES.GCM._SIV.open(ciphertext, using: key)

        XCTAssertEqual(recoveredPlaintext, plaintext)
        XCTAssertEqual(recoveredPlaintextWithoutAAD, plaintext)
    }

    func testExtractingBytesFromNonce() throws {
        let nonce = AES.GCM._SIV.Nonce()
        XCTAssertEqual(Array(nonce), nonce.withUnsafeBytes { Array($0) })

        let testNonceBytes = Array(UInt8(0)..<UInt8(12))
        let (contiguousNonceBytes, discontiguousNonceBytes) = testNonceBytes.asDataProtocols()
        let nonceFromContiguous = try AES.GCM._SIV.Nonce(data: contiguousNonceBytes)
        let nonceFromDiscontiguous = try AES.GCM._SIV.Nonce(data: discontiguousNonceBytes)

        XCTAssertEqual(Array(nonceFromContiguous), testNonceBytes)
        XCTAssertEqual(Array(nonceFromDiscontiguous), testNonceBytes)

        XCTAssertThrowsError(try AES.GCM._SIV.Nonce(data: DispatchData.empty)) { error in
            guard case .some(.incorrectParameterSize) = error as? CryptoKitError else {
                XCTFail("Unexpected error")
                return
            }
        }
    }

    func testUserConstructedSealedBoxesCombined() throws {
        let ciphertext = Array("This pretty clearly isn't ciphertext, but sure why not".utf8)
        let (contiguousCiphertext, discontiguousCiphertext) = ciphertext.asDataProtocols()

        let contiguousSB = try AES.GCM._SIV.SealedBox(combined: contiguousCiphertext)
        let discontiguousSB = try AES.GCM._SIV.SealedBox(combined: discontiguousCiphertext)
        XCTAssertEqual(contiguousSB.combined, discontiguousSB.combined)
        XCTAssertEqual(Array(contiguousSB.nonce), Array(discontiguousSB.nonce))
        XCTAssertEqual(contiguousSB.ciphertext, discontiguousSB.ciphertext)
        XCTAssertEqual(contiguousSB.tag, discontiguousSB.tag)

        // Empty dispatchdatas don't work, they are too small.
        XCTAssertThrowsError(try AES.GCM._SIV.SealedBox(combined: DispatchData.empty)) { error in
            guard case .some(.incorrectParameterSize) = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
    }

    func testUserConstructedSealedBoxesSplit() throws {
        let tag = Array(repeating: UInt8(0), count: 16)
        let ciphertext = Array("This pretty clearly isn't ciphertext, but sure why not".utf8)
        let nonce = AES.GCM._SIV.Nonce()

        let (contiguousCiphertext, discontiguousCiphertext) = ciphertext.asDataProtocols()
        let (contiguousTag, discontiguousTag) = tag.asDataProtocols()

        // Two separate data protocol inputs means we end up with 4 boxes.
        let contiguousContiguous = try AES.GCM._SIV.SealedBox(nonce: nonce, ciphertext: contiguousCiphertext, tag: contiguousTag)
        let discontiguousContiguous = try AES.GCM._SIV.SealedBox(nonce: nonce, ciphertext: discontiguousCiphertext, tag: contiguousTag)
        let contiguousDiscontiguous = try AES.GCM._SIV.SealedBox(nonce: nonce, ciphertext: contiguousCiphertext, tag: discontiguousTag)
        let discontiguousDiscontiguous = try AES.GCM._SIV.SealedBox(nonce: nonce, ciphertext: discontiguousCiphertext, tag: discontiguousTag)

        // To avoid the comparison count getting too nuts, we use the combined representation. By the transitive
        // property we only need three comparisons.
        XCTAssertEqual(contiguousContiguous.combined, discontiguousContiguous.combined)
        XCTAssertEqual(discontiguousContiguous.combined, contiguousDiscontiguous.combined)
        XCTAssertEqual(contiguousDiscontiguous.combined, discontiguousDiscontiguous.combined)

        // Empty dispatchdatas for the tag don't work, they are too small.
        XCTAssertThrowsError(try AES.GCM._SIV.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: DispatchData.empty)) { error in
            guard case .some(.incorrectParameterSize) = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }

        // They work fine for the ciphertext though.
        let weirdBox = try AES.GCM._SIV.SealedBox(nonce: nonce, ciphertext: DispatchData.empty, tag: tag)
        XCTAssertEqual(weirdBox.ciphertext, Data())
    }

    func testRoundTripDataProtocols() throws {
        func roundTrip<Message: DataProtocol, AAD: DataProtocol>(message: Message, aad: AAD, file: StaticString = (#filePath), line: UInt = #line) throws {
            let key = SymmetricKey(size: .bits256)
            let nonce = AES.GCM._SIV.Nonce()
            let ciphertext = try AES.GCM._SIV.seal(message, using: key, nonce: nonce, authenticating: aad)
            let recoveredPlaintext = try AES.GCM._SIV.open(ciphertext, using: key, authenticating: aad)

            XCTAssertEqual(Array(recoveredPlaintext), Array(message), file: file, line: line)
        }

        let message = Array("Hello, world, it's AES-GCM!".utf8)
        let aad = Array("I heard you like Counter Mode, so I put a Galois on it".utf8)
        let (contiguousMessage, discontiguousMessage) = message.asDataProtocols()
        let (contiguousAad, discontiguousAad) = aad.asDataProtocols()

        _ = try roundTrip(message: contiguousMessage, aad: contiguousAad)
        _ = try roundTrip(message: discontiguousMessage, aad: contiguousAad)
        _ = try roundTrip(message: contiguousMessage, aad: discontiguousAad)
        _ = try roundTrip(message: discontiguousMessage, aad: discontiguousAad)
    }

    func testWycheproof() throws {
        try wycheproofTest(
            jsonName: "aes_gcm_siv_test",
            testFunction: { (group: AEADTestGroup) in
                _ = try testGroup(group: group)
            })
    }

    func testGroup(group: AEADTestGroup) throws {
        for testVector in group.tests {
            var msg: Data = Data()
            var aad: Data = Data()
            var ct: [UInt8] = []
            var tag: [UInt8] = []

            var nonce: AES.GCM._SIV.Nonce

            do {
                nonce = try AES.GCM._SIV.Nonce(data: Array(hexString: testVector.iv))
            } catch {
                XCTAssertEqual(testVector.result, "invalid")
                return
            }

            if testVector.ct.count > 0 {
                ct = try Array(hexString: testVector.ct)
            }

            if testVector.msg.count > 0 {
                msg = try Data(hexString: testVector.msg)
            }

            if testVector.aad.count > 0 {
                aad = try Data(hexString: testVector.aad)
            }

            if testVector.tag.count > 0 {
                tag = try Array(hexString: testVector.tag)
            }

            let key = try SymmetricKey(data: Array(hexString: testVector.key))
            XCTAssertNotNil(key)

            let sb = try AES.GCM._SIV.seal(msg, using: key, nonce: nonce, authenticating: aad)

            if testVector.result == "valid" {
                XCTAssertEqual(Data(ct), sb.ciphertext)
                XCTAssertEqual(Data(tag), sb.tag)
            }

            do {
                let recovered_pt = try AES.GCM._SIV.open(AES.GCM._SIV.SealedBox(nonce: nonce, ciphertext: ct, tag: tag), using: key, authenticating: aad)

                if testVector.result == "valid" || testVector.result == "acceptable" {
                    XCTAssertEqual(recovered_pt, msg)
                }
            } catch {
                XCTAssertEqual(testVector.result, "invalid")
            }
        }
    }
}
