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

class AESGCMTests: XCTestCase {
    func testBadKeySize() {
        let plaintext: Data = "Some Super Secret Message".data(using: String.Encoding.utf8)!
        let key = SymmetricKey(size: .init(bitCount: 304))
        let nonce = AES.GCM.Nonce()

        XCTAssertThrowsError(try AES.GCM.seal(plaintext, using: key, nonce: nonce))
    }

    func testNonStandardNonceSizeCombinedRepresentation() throws {
        let ciphertext = Array("This is some weird ciphertext".utf8)
        let tag = Array(repeating: UInt8(0), count: 16)

        let regularNonce = try orFail { try AES.GCM.Nonce(data: Array(repeating: 0, count: 12)) }
        let longNonce = try orFail { try AES.GCM.Nonce(data: Array(repeating: 0, count: 13)) }

        XCTAssertNotNil(try AES.GCM.SealedBox(nonce: regularNonce, ciphertext: ciphertext, tag: tag).combined)
        XCTAssertNil(try AES.GCM.SealedBox(nonce: longNonce, ciphertext: ciphertext, tag: tag).combined)
    }

    func testEncryptDecrypt() throws {
        let plaintext: Data = "Some Super Secret Message".data(using: String.Encoding.utf8)!

        let key = SymmetricKey(size: .bits256)
        let nonce = AES.GCM.Nonce()

        let ciphertext = try orFail { try AES.GCM.seal(plaintext, using: key, nonce: nonce) }
        let recoveredPlaintext = try orFail { try AES.GCM.open(ciphertext, using: key, authenticating: Data()) }
        let recoveredPlaintextWithoutAAD = try orFail { try AES.GCM.open(ciphertext, using: key) }

        XCTAssertEqual(recoveredPlaintext, plaintext)
        XCTAssertEqual(recoveredPlaintextWithoutAAD, plaintext)
    }

    func testExtractingBytesFromNonce() throws {
        let nonce = AES.GCM.Nonce()
        XCTAssertEqual(Array(nonce), nonce.withUnsafeBytes { Array($0) })

        let testNonceBytes = Array(UInt8(0)..<UInt8(12))
        let (contiguousNonceBytes, discontiguousNonceBytes) = testNonceBytes.asDataProtocols()
        let nonceFromContiguous = try orFail { try AES.GCM.Nonce(data: contiguousNonceBytes) }
        let nonceFromDiscontiguous = try orFail { try AES.GCM.Nonce(data: discontiguousNonceBytes) }

        XCTAssertEqual(Array(nonceFromContiguous), testNonceBytes)
        XCTAssertEqual(Array(nonceFromDiscontiguous), testNonceBytes)

        XCTAssertThrowsError(try AES.GCM.Nonce(data: DispatchData.empty)) { error in
            guard case .some(.incorrectParameterSize) = error as? CryptoKitError else {
                XCTFail("Unexpected error")
                return
            }
        }
    }

    func testUserConstructedSealedBoxesCombined() throws {
        let ciphertext = Array("This pretty clearly isn't ciphertext, but sure why not".utf8)
        let (contiguousCiphertext, discontiguousCiphertext) = ciphertext.asDataProtocols()

        let contiguousSB = try orFail { try AES.GCM.SealedBox(combined: contiguousCiphertext) }
        let discontiguousSB = try orFail { try AES.GCM.SealedBox(combined: discontiguousCiphertext) }
        XCTAssertEqual(contiguousSB.combined, discontiguousSB.combined)
        XCTAssertEqual(Array(contiguousSB.nonce), Array(discontiguousSB.nonce))
        XCTAssertEqual(contiguousSB.ciphertext, discontiguousSB.ciphertext)
        XCTAssertEqual(contiguousSB.tag, discontiguousSB.tag)

        // Empty dispatchdatas don't work, they are too small.
        XCTAssertThrowsError(try AES.GCM.SealedBox(combined: DispatchData.empty)) { error in
            guard case .some(.incorrectParameterSize) = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
    }

    func testUserConstructedSealedBoxesSplit() throws {
        let tag = Array(repeating: UInt8(0), count: 16)
        let ciphertext = Array("This pretty clearly isn't ciphertext, but sure why not".utf8)
        let nonce = AES.GCM.Nonce()

        let (contiguousCiphertext, discontiguousCiphertext) = ciphertext.asDataProtocols()
        let (contiguousTag, discontiguousTag) = tag.asDataProtocols()

        // Two separate data protocol inputs means we end up with 4 boxes.
        let contiguousContiguous = try orFail { try AES.GCM.SealedBox(nonce: nonce, ciphertext: contiguousCiphertext, tag: contiguousTag) }
        let discontiguousContiguous = try orFail { try AES.GCM.SealedBox(nonce: nonce, ciphertext: discontiguousCiphertext, tag: contiguousTag) }
        let contiguousDiscontiguous = try orFail { try AES.GCM.SealedBox(nonce: nonce, ciphertext: contiguousCiphertext, tag: discontiguousTag) }
        let discontiguousDiscontiguous = try orFail { try AES.GCM.SealedBox(nonce: nonce, ciphertext: discontiguousCiphertext, tag: discontiguousTag) }

        // To avoid the comparison count getting too nuts, we use the combined representation. By the transitive
        // property we only need three comparisons.
        XCTAssertEqual(contiguousContiguous.combined, discontiguousContiguous.combined)
        XCTAssertEqual(discontiguousContiguous.combined, contiguousDiscontiguous.combined)
        XCTAssertEqual(contiguousDiscontiguous.combined, discontiguousDiscontiguous.combined)

        // Empty dispatchdatas for the tag don't work, they are too small.
        XCTAssertThrowsError(try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: DispatchData.empty)) { error in
            guard case .some(.incorrectParameterSize) = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }

        // They work fine for the ciphertext though.
        let weirdBox = try orFail { try AES.GCM.SealedBox(nonce: nonce, ciphertext: DispatchData.empty, tag: tag) }
        XCTAssertEqual(weirdBox.ciphertext, Data())
    }

    func testRoundTripDataProtocols() throws {
        func roundTrip<Message: DataProtocol, AAD: DataProtocol>(message: Message, aad: AAD, file: StaticString = (#file), line: UInt = #line) throws {
            let key = SymmetricKey(size: .bits256)
            let nonce = AES.GCM.Nonce()
            let ciphertext = try orFail(file: file, line: line) { try AES.GCM.seal(message, using: key, nonce: nonce, authenticating: aad) }
            let recoveredPlaintext = try orFail(file: file, line: line) { try AES.GCM.open(ciphertext, using: key, authenticating: aad) }

            XCTAssertEqual(Array(recoveredPlaintext), Array(message), file: file, line: line)
        }

        let message = Array("Hello, world, it's AES-GCM!".utf8)
        let aad = Array("I heard you like Counter Mode, so I put a Galois on it".utf8)
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
                jsonName: "aes_gcm_test",
                testFunction: { (group: AEADTestGroup) in
                    for testVector in group.tests {
                        var msg = Data()
                        var aad = Data()
                        var ct: [UInt8] = []
                        var tag: [UInt8] = []

                        do {
                            let key = try SymmetricKey(data: Array(hexString: testVector.key))
                            XCTAssertNotNil(key)

                            let nonceData = try Array(hexString: testVector.iv)

                            let nonce: AES.GCM.Nonce
                            do {
                                nonce = try AES.GCM.Nonce(data: nonceData)
                            } catch {
                                XCTAssertLessThan(nonceData.count, 12)
                                continue
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

                            let sb = try AES.GCM.seal(msg, using: key, nonce: nonce, authenticating: aad)

                            XCTAssertEqual(Data(ct), sb.ciphertext)

                            if testVector.result == "valid" {
                                XCTAssertEqual(Data(tag), sb.tag)
                            }

                            do {
                                let recovered_pt = try AES.GCM.open(AES.GCM.SealedBox(nonce: nonce, ciphertext: ct, tag: tag), using: key, authenticating: aad)

                                if testVector.result == "valid" || testVector.result == "acceptable" {
                                    XCTAssertEqual(recovered_pt, msg)
                                } else {
                                    XCTFail()
                                }
                            } catch {
                                XCTAssertEqual(testVector.result, "invalid")
                            }
                        } catch {
                            XCTAssert(testVector.result == "invalid" || testVector.iv == "")
                            return
                        }
                    }
                })
        }
    }
}
