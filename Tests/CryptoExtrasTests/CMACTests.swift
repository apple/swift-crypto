//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import Crypto
import CryptoExtras
import Foundation
import XCTest

final class CMACTests: XCTestCase {
    // Borrowed from CryptoKit
    func testVector1() throws {
        let key = try Array(hexString: "a60269f095ad3c3bafae907c6f215de0")
        let mac = try Array(hexString: "172084c3fe99fde4af29aa8e6e5fe1")
        let msg = try Array(hexString: "cead1c5af16ca89bc0821775f8cba8c25620a03dfd27d6f1186f75f1c0bcfe4a20")

        var authenticator = try AES.CMAC(key: SymmetricKey(data: key), outputSize: 15)
        authenticator.update(data: msg)
        XCTAssert(authenticator.finalize() == mac)
    }

    // rfc4493 example vectors
    // https://datatracker.ietf.org/doc/html/rfc4493#page-11
    let exampleVector1 = ""

    let exampleVector2 = """
        6bc1bee22e409f96e93d7e117393172a
        """

    let exampleVector3 = """
        6bc1bee22e409f96e93d7e117393172a\
        ae2d8a571e03ac9c9eb76fac45af8e51\
        30c81c46a35ce411
        """

    let exampleVector4 = """
        6bc1bee22e409f96e93d7e117393172a\
        ae2d8a571e03ac9c9eb76fac45af8e51\
        30c81c46a35ce411e5fbc1191a0a52ef\
        f69f2445df4f9b17ad2b417be66c3710
        """

    func testExampleVector1() throws {
        let key = try Array(hexString: "2b7e151628aed2a6abf7158809cf4f3c")
        let mac = try Array(hexString: "bb1d6929e95937287fa37d129b756746")
        let msg = try Array(hexString: exampleVector1)

        var authenticator = try AES.CMAC(key: SymmetricKey(data: key), outputSize: 16)
        authenticator.update(data: msg)
        XCTAssert(authenticator.finalize() == mac)
    }

    func testExampleVector2() throws {
        let key = try Array(hexString: "2b7e151628aed2a6abf7158809cf4f3c")
        let mac = try Array(hexString: "070a16b46b4d4144f79bdd9dd04a287c")
        let msg = try Array(hexString: exampleVector2)

        var authenticator = try AES.CMAC(key: SymmetricKey(data: key), outputSize: 16)
        authenticator.update(data: msg)
        XCTAssert(authenticator.finalize() == mac)
    }

    func testExampleVector2PerByte() throws {
        let key = try Array(hexString: "2b7e151628aed2a6abf7158809cf4f3c")
        let mac = try Array(hexString: "070a16b46b4d4144f79bdd9dd04a287c")
        let msg = try Array(hexString: exampleVector2)

        var authenticator = try AES.CMAC(key: SymmetricKey(data: key), outputSize: 16)
        for byte in msg {
            authenticator.update(data: [byte])
        }
        XCTAssert(authenticator.finalize() == mac)
    }

    func testExampleVector3() throws {
        let key = try Array(hexString: "2b7e151628aed2a6abf7158809cf4f3c")
        let mac = try Array(hexString: "dfa66747de9ae63030ca32611497c827")
        let msg = try Array(hexString: exampleVector3)

        var authenticator = try AES.CMAC(key: SymmetricKey(data: key), outputSize: 16)
        authenticator.update(data: msg)
        XCTAssert(authenticator.finalize() == mac)
    }

    func testExampleVector3PerByte() throws {
        let key = try Array(hexString: "2b7e151628aed2a6abf7158809cf4f3c")
        let mac = try Array(hexString: "dfa66747de9ae63030ca32611497c827")
        let msg = try Array(hexString: exampleVector3)

        var authenticator = try AES.CMAC(key: SymmetricKey(data: key), outputSize: 16)
        for byte in msg {
            authenticator.update(data: [byte])
        }
        XCTAssert(authenticator.finalize() == mac)
    }

    // rfc4493 example vector 4
    // https://datatracker.ietf.org/doc/html/rfc4493#page-11
    func testExampleVector4() throws {
        let key = try Array(hexString: "2b7e151628aed2a6abf7158809cf4f3c")
        let mac = try Array(hexString: "51f0bebf7e3b9d92fc49741779363cfe")
        let msg = try Array(hexString: exampleVector4)

        var authenticator = try AES.CMAC(key: SymmetricKey(data: key), outputSize: 16)
        authenticator.update(data: msg)
        XCTAssert(authenticator.finalize() == mac)
    }

    // rfc4493 example vector 4
    // https://datatracker.ietf.org/doc/html/rfc4493#page-11
    func testExampleVector4PerByte() throws {
        let key = try Array(hexString: "2b7e151628aed2a6abf7158809cf4f3c")
        let mac = try Array(hexString: "51f0bebf7e3b9d92fc49741779363cfe")
        let msg = try Array(hexString: exampleVector4)

        var authenticator = try AES.CMAC(key: SymmetricKey(data: key), outputSize: 16)
        for byte in msg {
            authenticator.update(data: [byte])
        }
        XCTAssert(authenticator.finalize() == mac)
    }

    func testWycheproof() throws {
        try wycheproofTest(jsonName: "aes_cmac_test") { (group: TestGroup) in
            for test in group.tests {
                precondition(test.flags.isEmpty)

                do {
                    var authenticator = try AES.CMAC(key: test.computedKey, outputSize: test.computedTag.count)
                    authenticator.update(data: test.computedMsg)
                    let result = authenticator.finalize()

                    switch test.result {
                    case "valid":
                        XCTAssertTrue(
                            result == test.computedTag,
                            "Unexpected invalid test \(test.tcId) (\(test.comment))"
                        )
                    case "invalid":
                        XCTAssertFalse(
                            result == test.computedTag,
                            "Unexpected valid test \(test.tcId) (\(test.comment))"
                        )
                    default:
                        fatalError("Unexpected result type")
                    }
                } catch {
                    XCTAssertTrue(test.result == "invalid", "Unexpected invalid test \(test.tcId) (\(test.comment))")
                    XCTAssertTrue(
                        test.comment == "invalid key size",
                        "Unexpected invalid test \(test.tcId) (\(test.comment))"
                    )
                }
            }
        }
    }
}

struct TestGroup: Codable {
    var keySize: Int
    var tagSize: Int
    var type: String
    var tests: [Test]
}

extension TestGroup {
    struct Test: Codable {
        var tcId: Int
        var comment: String
        var key: String
        var msg: String
        var tag: String
        var result: String
        var flags: [String]

        var computedKey: SymmetricKey {
            SymmetricKey(hexEncoded: self.key)
        }

        var computedMsg: Data {
            try! Data(hexString: self.msg)
        }

        var computedTag: Data {
            try! Data(hexString: self.tag)
        }
    }
}
