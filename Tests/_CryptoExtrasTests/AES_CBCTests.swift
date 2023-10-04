//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import Foundation
import _CryptoExtras
import XCTest

final class CBCTests: XCTestCase {
    func testWycheproofDecrypt() throws {
        try wycheproofTest(
            jsonName: "aes_cbc_pkcs5_test",
            testFunction: { (group: AESCBCTestGroup) in
                for test in group.tests {
                    do {
                        let decrypted = try AES._CBC.decrypt(
                            test.computedCt, using: test.computedKey, iv: test.computedIv
                        )

                        switch test.result {
                        case "valid":
                            XCTAssertTrue(decrypted == test.computedMsg, "Unexpected invalid test \(test.tcId) (\(test.comment))")
                        case "invalid":
                            XCTAssertFalse(decrypted != test.computedMsg, "Unexpected valid test \(test.tcId) (\(test.comment))")
                        default:
                            fatalError("Unexpected result type")
                        }
                    } catch {
                        XCTAssertTrue(test.result == "invalid", "Unexpected invalid test \(test.tcId) (\(test.comment))")
                    }
                }
            })
    }

    func testWycheproofEncrypt() throws {
        try wycheproofTest(
            jsonName: "aes_cbc_pkcs5_test",
            testFunction: { (group: AESCBCTestGroup) in
                for test in group.tests {
                    if test.result == "invalid" { continue }

                    do {
                        let encrypted = try AES._CBC.encrypt(
                            test.computedMsg, using: test.computedKey, iv: test.computedIv
                        )
                        XCTAssertEqual(encrypted, test.computedCt, "Unexpected invalid test \(test.tcId) (\(test.comment))")
                    } catch {
                        XCTFail("Unexpected invalid test \(test.tcId) (\(test.comment))")
                    }
                }
            }
        )
    }
}


struct AESCBCTestGroup: Codable {
    var keySize: Int
    var ivSize: Int
    var type: String
    var tests: [AESCBCTest]
}

struct AESCBCTest: Codable {
    var tcId: Int
    var comment: String
    var key: String
    var msg: String
    var iv: String
    var ct: String
    var result: String
    var flags: [String]

    var computedKey: SymmetricKey {
        SymmetricKey(hexEncoded: self.key)
    }

    var computedMsg: Data {
        try! Data(hexString: self.msg)
    }

    var computedIv: AES._CBC.IV {
        try! AES._CBC.IV(ivBytes: Array(hexString: self.iv))
    }

    var computedCt: Data {
        try! Data(hexString: self.ct)
    }
}

extension SymmetricKey {
    init(hexEncoded: String) {
        let keyBytes = try! Array(hexString: hexEncoded)
        self = SymmetricKey(data: keyBytes)
    }
}
