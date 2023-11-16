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

    func testNoPaddingDecrypt() throws {
        let testCases: [(expected: String, key: String, iv: String, input: String)] = [
            ("78fce24b9328634b8ddb11103b506ce5", "e34f15c7bd819930fe9d66e0c166e61c", "00000000000000000000000000000000", "3565a427a51707be5645c47f72d692ee"),
            ("a7f61f2f10d21699a903186a9a0ff14d", "5a276fa79d8355006193e90d6ea2cf91", "002f40993d50665ad1f3a3d7d4969d8d", "fe0a7d603167b1608abe6f1494b2cafe"),
            ("27182603846e0623333d32c549269019", "f422c5bfbd6f17a40e71dd565358ba0c", "aec640509d4f9e79d27fa5802145a326", "eb1e4918d22f8bbf0081ee83a5c6894e"),
            ("da10f19282a591787850e12bc6f1a1cb", "49601f214934e73ec0cd8dbde4feae87", "ce08dcdb8443e8e9130853b0b0ad4301", "733096e3b500213f2c1b006a1f81dc68"),
            ("3509abdde2bdfa33fb9aa1870f03d889", "f9ef0afb0447ce4d7820c9c17e41fd71", "941c2c9e47ef63794b42f0b77c73bc5f", "0d01156face0a6b42bd8b256b6f30ff0"),
            ("092e1108b6c20c2c30b27c398aea93a0", "5b5d0d65810287f5847e416af17db6e5", "49bb51bdd987606ad48f19d1876c6fd3", "ff5bff77bc9693f92cd33f584a7ea0c3"),
            ("77eb4469996212490f0a850833416bf3", "aa769ffe1cdf1e5e54acebcefee0559a", "33afb772ffa25936b0c74d5c62498455", "5ab40cba136690f567b8cf8533dd469f"),
            ("0024357fd7dd5444d9fcf7d5318723c7", "f2023286030a505cc68a256035d23ac9", "ac4ded3df6f56836af3bf2866ea1328b", "821f516fb0991c6ecb73f880868db9ea"),
            ("b5a84318a08d9b3f7d2abbed6a3278a3", "48bb41b17719906487ca72f7dd3d5c4c", "6c0571b86aea62759c86f58855c5384c", "4eda4361324eef76aa4bd3337a5781f5"),
            ("4a13652effccef614295966cf199bddb", "a8ce1d88dfdc2d379cf99d03bdc918f9", "2251479e8a892e428b093f4625969c7e", "6f4500899b7ca94c187d5e865ae91664"),
            ("05c01827d89966c0a4c3fb42c10a6f05", "fe94d99630b1a58ca7695e0367dd979f", "979a32f2630d7f4085ba943ed4def7e1", "59d61a3dda52e1a61681b16970b2cc5e"),
            ("b031a5f6038112cdd39e833b1085fbee", "503ada9070ec79c69aa5ac8dc0831124", "20205f850ad7d19e18d4d4181771392f", "a376f68c5318925c6901362676e92ef8"),
            ("4e2f3d94c0997f6341ccf400acbfa8c3", "22dec1db960698883fdcec56499d95c4", "b1363b50549a181246c4585e281c4fad", "deda0e17f77ead80af5d4f11246da13f"),
            ("96990732dbdebedaf0e02a2d79659702", "741059a41454ea8a768722eb41df5863", "3977497e5c4bc1f81b3083ea6263c9c5", "9fb1448bab9a946cf79d386d354eb5ad"),
            ("0644906f602c3c95d0ff0587aa9f5fcd", "59e41d60aa6cf4a7894ce0b046d0fe46", "9ee5a10f3e16a7ca5977620690a97266", "6e4acf304242d216184c67d5b1bf6979"),
            ("f1a937f5b8e5f2638a3f762f69de322d", "824ffd96e3dbacbb472c2b01cb21eca0", "27105d411abd0d8811dcc9a2c68af6dc", "b4a1f51d7fe0f4f36bfc4f402ca44a94"),
            ("845e92b6ffc325cb56aaead1e7d9dba3", "03375d8a02e1b034efa8b69dab0c336f", "c7ceb03f879ee97c7bbe2e116fae10e3", "268bdba7cf5a97eff56cefd3d8d9cd8c"),
            ("2b370f431da3116dcbcde780604f79a9", "88d6fd4588577ec40531323a1bf5d0e7", "601e4012f62ff6b37decea0dda744141", "1fd3d22c1cc3cf6b954dd05c78211577"),
            ("cd4796c2c6c2c948c7e3dcf15737b70c", "cdc5ed0f785b3c2cb98eeb95e7b463e7", "bb87d54bd8284b174a5e6195d1611326", "fab31986ed041e7b6022748d8a3ea4be"),
            ("01ae03a640276d1d8754731c0920275e", "9555fd443deacf93679a3687e4c04f4c", "2e7a58872fe362552ec07ce085aab64c", "101c381d723f29042253d12c094b9652")
        ]

        for (idx, testCase) in testCases.enumerated() {
            let iv = try AES._CBC.IV(ivBytes: Array(hexString: testCase.iv))
            let expected = try Data(hexString: testCase.expected)
            let key = try Data(hexString: testCase.key)
            let input = try Data(hexString: testCase.input)
            let decrypted = try AES._CBC.decrypt(input, using: SymmetricKey(data: key), iv: iv, noPadding: true)
            XCTAssertEqual(expected.hexString, decrypted.hexString, "Unexpected invalid test \(idx)")
        }
    }

    func testNoPaddingEncrypt() throws {
        let testCases: [(expected: String, key: String, iv: String, input: String)] = [
            ("044e66cb71f3266fc1399c6c782ddce8", "5b6fc08df9b778d11850356b8bfc9561", "50892a30aa3ba6834529bfd222836312", "a4bc6641b46d1390dac577e3236f77b0"),
            ("386eb70572accf30fe9a3d75d06eafe8", "4c1f218e634762237a06e23d4c591592", "7c0a63723204260ce5650c771e3fe703", "98bd568b7527b05bf3890ec78630a3a8"),
            ("71f9696770fd8545ab1c863965513fc9", "7a2c634ddcbc514b2f7840ca7d2a651c", "31824a5645bd35184c9f131038b9e58c", "0ed7ab9d79dfc978f1c4c3a693c57b07"),
            ("035cc6f6f4f2c6815825d63e94e667e5", "ac03fd1fdedc70daa79413dd7bd4ca7d", "c7dacb70dfbc5e83c5d2cd9e78b1f7b3", "56c3983eab37c0c03bd5027584e84799"),
            ("5381a2240a180ae79f47cc4ac113e807", "d49ead66237bf075038fa7eb78ecf79a", "5de66c802468b92137be892544346ef5", "68f839a1b3313753bda3f96a3a7ea2cf"),
            ("afa522b4a76f93190ab047fa2782a511", "910c3c731f8761ca7f50fc90a209d5d5", "da42953d067b003e3d4b84d74c96fb00", "578b57b58e5fd2a37238edfba99c156b"),
            ("e2ceb699c7483d0c9a70f079172912b9", "ccc090bad8122fe393ae7fdabf3760b0", "da834aca9e71333297dfa0bc7bf79cad", "0156b24df84628e16d49d2486eba388f"),
            ("23e7efe7a992ae4cb6c01a1669da160c", "e3ed08506e19f2aa0f8c8a7098ce7135", "c21caf6d6572e8a1a15c6e3ff332bcaa", "b48c13a9f0a613bea8e3a924fd5c3e46"),
            ("5ed46772ac4cfaece41390e9acca5661", "9d06640350fca822be3d9e894ac847f7", "3194e59708f7e7b4d2eaf9994dddd78b", "a6b6ed260692bddeed425a1d8258fc3f"),
            ("0da63c81e8ada2a7d9654165649b87bb", "6a3f0688e227e33c8b50a5dc98e7154e", "85318f33f59484de541a3b0cde865cae", "71c7d787f357a98933fab9bdb48a175a"),
            ("2387ff8bd2bbbc34b699c104d64693a4", "315ed1c70955835795f3d8275b85ad8e", "f9e10dd2c3dad70697abf11ed8b71278", "0697f7dd1b5004815d51edc0dbd68293"),
            ("fb3a73824271ca4abe2ec8cdaa91ff8b", "1f9a0c54139b9245070f377a61f9fdd2", "3d3dd094ecd2576bc929c2acaed9dc25", "2a47f12b303fb5cfb1d767b08f7ee457"),
            ("22dd960d372d88b57fe8351a18e545a6", "00bc09b5d80e3e81e11b503dc6bc941c", "f81de2afa3cd7f107cc4ed23fa6d56e4", "e9e91acd36b429e0bedc93586848a982"),
            ("7b4edea22224f2bf2da8c66a2ff14c40", "27c6b62afca071c875f6264156ca5726", "d651c307fe52886d6d32e08c6bce2593", "d58d653b9781ac6e619e80930a903306"),
            ("72180bfc30086e99a7c3f078af15efe1", "6e03ade9458c331e7365816ce31adf9d", "9a5066792ca53d1cbce393c04258baf3", "efac4556f18f5e84d65474f3d15500b7"),
            ("8e8242d5f890f78ed5dd5b5026efa350", "f7974ffcaf62087e65a485ce28c0e6e3", "adba74227dc1dff05a7a0025849061ed", "5dc948c8259fd754b85511600a26fd4a"),
            ("1fcfa8d78148477e9da4a91ac735abc4", "6f79fdf41c2311b96769b9cfb12169a0", "6c5a1b12ee9ef24f549c6f71aeafa6f4", "5f43a866d33f92e41c9821fb0cee6726"),
            ("5d0aab0ea2010b0814b78a33990428ce", "9e19f1b44e5c1745a2759f07f3d73be5", "78958628e0222f7d8f8bb0d9df0e3bc6", "529d390a7855930c5bf261a48729762b"),
            ("5da3872d74604481ecec71f0dac683bd", "e3e976f89cf07bb01854d37d89a0777c", "5c98357f363820b7e9567aa8d414a58c", "2d4b5f6f1f8bc19d4d86fb1d1f06021d"),
            ("594244612d8128ae3c98b419f4535f6e", "f0f8531c4e1531cf12378176300556ca", "4e9cafd216c802279cad591fd1850ba7", "0d3eb25245e50f9df088e296223b5fb4")
        ]

        for (idx, testCase) in testCases.enumerated() {
            let iv = try AES._CBC.IV(ivBytes: Array(hexString: testCase.iv))
            let expected = try Data(hexString: testCase.expected)
            let key = try Data(hexString: testCase.key)
            let input = try Data(hexString: testCase.input)
            let encrypted = try AES._CBC.encrypt(input, using: SymmetricKey(data: key), iv: iv, noPadding: true)
            XCTAssertEqual(expected.hexString, encrypted.hexString, "Unexpected invalid test \(idx)")
        }
    }

    func testNoPaddingEncryptNoMultipleOfBlockSize() throws {
        let key = try Data(hexString: "b6fc08df9b778d11850356b8bfc9561a")
        let iv = try AES._CBC.IV(ivBytes: Array(hexString: "00000000000000000000000000000000"))
        let input = try Data(hexString: "6741b46d1390dac577e3236b")
        XCTAssertThrowsError(try AES._CBC.encrypt(input, using: SymmetricKey(data: key), iv: iv, noPadding: true)) { error in
            guard let error = error as? CryptoKitError, case .incorrectParameterSize = error else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
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
