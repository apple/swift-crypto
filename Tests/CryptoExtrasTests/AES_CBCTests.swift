//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import CryptoExtras
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
            ("01ae03a640276d1d8754731c0920275e", "9555fd443deacf93679a3687e4c04f4c", "2e7a58872fe362552ec07ce085aab64c", "101c381d723f29042253d12c094b9652"),
            ("515d49c24105a289c1a41f0a9d401918c29fdff9aed3cfa04a63737171b58f6814488b198bd76906da1494a55dc8747829690ab45c17ef37e90eb6aac5dc0c517033498cf2c8651ea4712cbd9158bfda91ebdf5d354b78e4d4b7f589f1639ff06c69004312ee6d3ac5851df2573880d60854ddb693664805e20119802da92e735a744f4b50f532ece64482d51bb0dd5ccada65471ad0c930b16391533ed0df9718563c671ec420f6cc7feb8cf1221cb5ba880e41559c1426c2db475ca7e89bf3a97ec87d0fefabde224314503ad3d70e14330d6ec2e13dba6af224c0101c3cfd6f3c7d599a1226b2773812b2731ced1829221874cec1d1e1ebe62d1bad509806", "4afe0482bb98576954faf3fbd50ed836", "cf3fb2b7e6d5cc0b0255ce6e9c81c8c3", "d19c26dbbe46ddaa301a3bbab63eafe6ad567cecce16c9658e550d690e51c89d0061aa1310dd979f2b06b9b57bb10b6018ec9c5bd0ab34430166afd6b1a8d88470ee35177740fb3e2450ccd5e937876b5b193b2c7e24b3133c018cd8b6daf7f50a5dd2ee4cd8f0e08432ff00e7ee8f6b88540447191b4ae90e305bcd4761b215095a13cf0bc8385aa04b2dc051b32c06ebc08ac729fd0e328a098d095681a3163d89f22f696b5cb3ace072f74e6e2c84c91c0f4d5fb9311c6d2b358e5c93df20fd64097264fe27f330ceda139b1fe80ed9456f6cf253cbbd59bcc06f3b7ba2c3e6fe2e8eaeee18cff5abc7c87d1b9ba54a2e38fd39dc482152e0aecfd13f43e6"),
            ("26bebb56bb51e9a0bf1d5ebc327d3b94b6a00e3ee041742175feab2c23223a1950a3c6b93a4cfd389edb924d8fc616bba5cd82da7ed6293faa9f54d036953bd0bc70b9b22aec948d1cdddba8d67d49a50ffd9fa5202c7020ef680c97b6a56fede3e31feed037995e072b235ded7c966605423ba342d7cafdf204b18af46f145d8e750c4d129c6284df08851bc81b69624a5b6c550e738bbfcf06123d0c67267868fead79d152a5185f517dfbab1b69cdc414ef4e3767b3ca674cb0994a455b4776a6056e103929ef7c50270ab2feef44f29ee144bd555d003f4deff3ef3e916e2e7ffda6d6c5340e8ea24c2a9ed25d1d3356238efb995c0a95b62cb109158bf2", "79c661f1f8dd14c8c618f391a3fe058a", "a3bdd75e51b33c9022b93143b12e3917", "0ba042d4d93fdc7559fbf43574fee5b899ae41a7b9c74f4b59d73a5c7885753e6867a15f5d822beba9729e4f7a571084af831ad1270ca4a77bc8326473b4028a2664d637bcbd9c7d1b17c3145f82116af3f5ddb75e64b11e42f0fa512ea9da97e804c02354295cc4518708898eae4e2c6dc7ea0f52e9a96f68f4747e2227b4105fb9400eaaf12dfb8223354f68a4b1027a1a5b3eac2dcd760a9c26755899faf739b56fbb235c7564c9f7aa91aed52d1206db3fbc886f88620825cfa22aeb6b782abea2c8d9afcabb14f10d8b8904826de99d0590fa4eb6003fc7af173aa3fac47872467ea37ea63937f9a6acb9b619e3d8b355a1e6a9818b2793963e226327be"),
            ("d94de8ff5a0f4c691d72c237efede3b99039043ec3b936df2c69b149021c0baf01c78e951c0346949b783a07600a0c40ecb9f7196d39dce4217f0473f921d2ca90bcdd154a5330892ccced5566e96d11fa25b605e5622f840d7879249c7349f6134c47055edfbf91d67b18d93e3fb9da36cd530f8ac1586626f2b370cb41bf309e84d20447e1650cd84d71260f9cc882f4366f0a4acec7eca72051dd2c2940fd69c158c8163ca70774018c467e319fec1395001c48a6939537202a500881473d6b5abd158adc0f222d7c1480ec09c3d476f57f276e13aa32fcdde3f746d8e50fc38877b24607a90d055dc94d388b272f932056c7938df54f2f72e8a93435081c", "5e0c9173371e9e409fd4c95b4062f743", "d759b55f85751615db8fb68649e365b9", "3b2f8874f757e604af5f643b65513bdeee5a07f563af980c65b76007fe6491e00449c817619237a752e302946269537cb88373d5729e0f5bd92b763152d4f2af89bc5ab6c62d42fb3748f78a76775e7067789aa4a9d8f90e10a79addfdb956f1fc2fd004ef9d19d610fa28d55fca1a853a0ce33f9f433607a8988d18d9aa4019363c40eb78ddff6fc9a83d21abe6571979e7c7072c3035b762b45992ad7590b95045cb15d9f60f301edfb0f8e44a57260f273e0e5c43e2f8e7c23c5d233c441841e76f934e7523856a844f6bc2ba6bea8a63b9fbf46e4bb415e06f0d49ee918aab08198d16b82b23e05bfb0c9b98b76182972d59b9750513ff1437d516c77e59"),
            ("202aa99c2a8494479f6277d350b6ae57cf9505684da34ad2ffea33266258ca6337391d0897cb4f547ed25c14058a602577c641a68b77f8bd8061bfb6ceb8f932f258747e9aa0c197fd3f4e8131ef4077", "26f7045a8639d07c1ae4c68639b1bd83", "015683c1840e2e1aa43950b99af91abe", "223a592d75ef02fcde6c4a54d29d20bf815d4d1330a5b0c985526dab2ecebec57c42970720b3874f9760025f4445eca8b395a47bf07f726f9b8e742244fdab34ac8599e5dbc4b9e92800b8165553b81c"),
            ("40c5c1d557ca4c6f682aa1edb5c0d55f75d9bd5256477bf04de7966152e6dbaa244fa9b3a5922a7296d13ff30fbff2aacac9a184de245cc7273e28988ed184c1309959e2a1ad7944220fba7fceabd59ab2dacfedc52a808517a39a9edbb8ad6ec06d44da5744f224b533d88622f52ac96d6e3b3a41cde97a1d26c724c7bb1eacedfa5e4174c523972a6c618a40446d43", "e75d109520355b373b937605cfe2976c", "187d8598c1bc83401d90e13399354d6b", "13d49e98efb965732d8200ba9b2e5ff938dd5d51497ece6c93bfe1a7fe1102259d31d13a77c0943f37bf66ce8ee2c03722c248088e42cf5f6a7ea23300ae61a46b72de0326254cad8b94d508dd6fb79a4e4eb0f5853207da08033a951bea927217bb46776fb70a5b701bc9e786d270023a2adde87fe60f654b6b055d9b994b138b279304a4b0bed3f6335af7798a2ff7"),
            ("bdf7516ebf98f13c858a8beac67be78b384f63206682cdfada511b1479dbcf02715fb7a16b2aef944a7c53ffcbc345fb40ccf4d75cdafdd0f1cf8a25859dc5df7932fc6f60a53060b60da17e8f76198db716eb3a0d57975999233f427d535bf4e459c52ee4451d21a1f11b37b8c277fb641adb3812a4165b44b1e6df6d05c96edb71ccf166f788d76bf2538460c6a7db80398a99abf988e95a56bbb05ad946dd37111aa1ea00102228d039cb165f1d40c561d86ca747b9fe771479279dc90e9b52eee111da6a87328d118e13a5698ab3", "c74c99b7dc386316ab59379e884b9918", "bdb807b8797fccd4ac2c11d7b39d1335", "6bb287efe64633caa4b9b8e693593923c45cf94d74135ff0744d11e5fdb04133bcd05832260ab6d66e3f78800d2c67019242a63c3bf9ae2f42ae919b63c4625df2c55049719cdf5d8d91d94db10a8abed8fe0d6d1a5a07bb0b2bfccecc8b20508d9d596c5ad90ce03afa6e1f797baa892d91f4de784936d57d458a11289eacb2790c989db9c39160ceda4c08effa93499d451ea91be9e32b0da6f89ce8fab06a4ca1847567a9034f142906c70e333c97a8b2fd6b1b1fb3490ffc3413799fc4c6bd39ef064563f64dc073286c338d7990"),
            ("15f8e50c5ab60324d968dd5072e19c86440836a0f5b44da1d0bf6fd05038e322f58d9f469607d57de54d3b6d4f11292a02fcbad5f5aea6d589a06704f034135229c6dcd17905b3a50a82d08e11fef75208c6eba54e5f07c0e5b2b7bc62950d2890a1097302e8bdf8557c05d65851f0634d96d2c89963186df0d086aac19fd65f", "77167a078524ab66506c15d1ab676831", "2db4866e449fd0accbe55b0451ba5565", "0d05752c98207bee2bd72b1f0d71b614a5488ef335a01868fa9926f57382fc99233165a4834bfcf9923c0c1beddee34084d859868ea2d93e3edb6992dee2f29ad2419facc23e4ab7e74b0a8deaa04a1d1fe29bf34b76c351f4cbc455446a1b2c3f01b417941856439c001af7abd911f89d9060635c2ed1eb41679941b673f41c"),
            ("42ad0548e0d2dff3e2eb2e8154e5ccfca6d37cad2b42d3a438a4bd6569f99c36", "39fbece97007b404934269229a812f19", "d71830cdf56347d574816f2dba8fcf55", "c1e28dd34307e8f6a452cc9e8c8d99ecd1aad5382b01015d1565820bfe07f779"),
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
            ("594244612d8128ae3c98b419f4535f6e", "f0f8531c4e1531cf12378176300556ca", "4e9cafd216c802279cad591fd1850ba7", "0d3eb25245e50f9df088e296223b5fb4"),
            ("9e039c96909b4371f04e4dd4452980ad5b1cea18e499b617490b0d252d329169b05a63e1e5d3b398fc4cdd8fc21dc6343ac71f6bc45b5d1912f4a9d0d8e692ea1a3d488fbe778b696db44fe830be4b0455e7399cd0bda8a20611bb1f53d84dd6b3bf82097565b464fc87ab03cbf8c0ef", "a9f1f0aef597dc7ba50b84f4ba7fa868", "99e53a4554cb34246affc615a27193b0", "f5cf1cb839b497360126fb3e537dabd2945ecc19d99baed91746a2c037b377bde2640b87c98d51bd45ff0dd172ceaba7efe3cb1e7460061d6a17fe18c1da96aaf175975b1d2f86a33f86443cf6b56fc28a35a4cdbb4b042c8bb6290fbfab52434ab02cfa69cc8db5b7fb864585299db8"),
            ("f292e0b4f2193f2ec602fb904557951a694f12ec7dce04d011b69d0ff2b09db55da325c7b191d525dd66860440c4b6607b49a3d9de04bf3cfde0516b5b4b2327d62a13327ea6e787f9372f5f49e3e22b93f08d8f33a49d8b36407bdb5c7d794be5cd8f1a3b1b7d13d743aa4fbdfa20bda74fede5aa2a70758a5df3c2b5cdc9540e4c97183c5ad240fc567cac4e6e0f59cefce489aee42cad5fbbb4865aa1f9dcb366fd04ee431d5dcf9c6f03f6eec87ec3cc6dec46440614a5b2bbca7e17f4520d6a7b9c6b93c7821f0622d55a65202726376b9efc15ecc20b877d2061178dd376f28c6f60011d88fe5554bb745cbd79", "c8e7cc8db09daf07ec8ac1b02141f840", "b2346cc428bab7ff3e8ca0221c28262a", "db79d6d7f33bcb6130a16901caac5867590fee02fa53382b86421dbb4be3495053bf9d0001c35f8b2ac64af0a29bd123a76b54bff725d408c4eb04ba48a26576213e68265ae59ee5f11452d8f392b55ec592f229990bf3f2cebbcb974f58f76b4d8894af64bdb7404c2e138d137897635a082808a50a953e0e3f799c8b2657f7adb13f17be0ba398cf2e77732d642de8b4eb7c0391344fbfb8bb6a460275609ab9ea9b33cd119934fc35df411a5ec1dee0de18a8b26fc5c703daa2d22f2f80050e3d82b0ff51e9cea1697892ddb4c41ef7b2ed650db35026ea936439d6930b754e77e81d20053b902eae85db6c45dc39"),
            ("0bb2ea7e38f992838f6b28e9babcd911afa9cf69dd19109b7f660704972b5600fd40f21817ec1243e9672a1c74c4ab64fee98b8dcd911d11d9ba3b8ef50ff892", "22cd2c1c879b2d3004d1b74308ec7919", "4962c42705186ecf3e18a67fbbcdf217", "762b4f8647d0c7b2e2bb064aaba44b38d8b98c53f397fcd6152926d461efdab077791be226a5a62db787b797da42df3311ba220777135610e4c29ebf9d9d62a2"),
            ("e4a9dc17294ae50407093867311f47b8d7d6ceca5e311bfa957c429f22598bb1524a66b89d9ebbc3d27a77d6b86ae17a945cc518f91214102d9b0bb562587ccbe76c8aa8f2d4743491a0b9dcfeff2429b99986b87ed70f83907ff01438f46da9d6092f6d84d3d791bb8f2110ebf84627", "61600d387103e77cab3298c5e8a64078", "91eb4a0e1f2ec8a22551cb1cfea136e4", "ed15f82a41cb73e906a2ff9234d591b3fe3e37d269868b04dd7c3805ea91dc9f590fc625d6f455da6ff6d51855e33a872c616678f1fe81c62bf26598aaa301f250ffa9eb9427eeab07e00eade529962ea7651b6e4b2903525873073f50b3f6b48949db26e685175c77f8de452a396ae3"),
            ("eccc4c0ee1f7b9fb45e4c4044207c6135e3c07d32e5a04ef1619f55b85889ac7ea7e8925912b32a273d27619ea6427e056f7de1f4e1d0d8f9057c75811ecdc2e", "bccab4cbe33eee535ef1f305c08df7fc", "9de08a016bfba82579977dec588f6e0a", "a207f44be5df4ed36423b570b75672b4a80397496fc9aa34565b2975a1e6ee047f95e284fa9a10954dc01686f5239b6d995e6165139a3a81bb81100f2b9ab831"),
            ("e86912d9216dccf4c2db2a424e70250a085d39f4d84311a8bd1e2380d5ec51a6", "db50aae05cfeddb67f5ec749f3f071f2", "847e845bd2f9a08a2a9567558b576932", "2f62fd594527e235b3f177a87704b9a1608158e49828ee6c263534779bbbcf28"),
            ("98daf5a22d2a00db01e44c0d473a9f685c9fb06c6018c26a082ff45371b89e891a64ec7dd98e1fc22bdd91fe5bb4a2a17b85a7e48a9c66b550fa5f32cd7ff2d4f4a7da84e9dee9e4ea2c7ec2b90406adba7ae4d880a55a79cf3d37fbd601f3f144d0d9283041acb073945240f2b27e449c889d9c39ba6599adc2133fc52dfa22f68bc0a7d72fdb83f4ade3da41532c7f596ff7da257701e692fed81b76fac200e94e0bab4da33b82baa02e54981022a5fd41da9a022b60093c68d0ad6c7a5f2cbb7bf895e8b4911f69675d548d3a01c7", "26bf69daee57cdd3bad68e17a50fdf51", "809351f931f7415943d2f113ab9f3c7a", "247130e137bff24b46a4dd4b475a272aad95d0e43b691b244873c0fb9a1a4d0cc15b5e2c8e609c584a5cc97bf2a4b0143df767dc81764a3908bf43bf0d4a1be3af61689a056165a93857be17a6514ba669f2f47008d3a145c99eeae7e48e8ecea1b7fcc8b55b9a275f1f20d5f0df1f6684027d658a85c5bcdc90438d00e30d7cb52f8a6ce620e2220202831f2f3fb838ce2e7073e9b0320079a7aa578e43f7a46646f6ec07dca863683a919ca8c54f618b572c94b723f0a241e46594b8ad16e9375d1e03c9faabd37dd7670684d5c398"),
            ("fd19f5565a6d3c903735d32f776728da49bd36e2388c50eab8cedb39eec711a901e5ccc13245afeee7426fd63ce57d11309837911891a40778b86f46aa2e282c328cc00b29be8ac9992a529e0bb1612509004b3b6109d608d55cfa8d01d8f55756ee34757574bea50ad7fb246467a787ab041df544d2af4184f055ba3d77984914675039d3faec3ac19a26ea3b886df5f04e4bbd1a189b08ee29423b8244da495b06e85f4a46a94f0c969c9d7eb2f481abb78338cd8d2d6e9372052d88cce4dc7ca75727f671f20929c9767b881fe6f0b9159f0d9948469f469463d3abeae4c415bcbaf39ff998731db82ad5b55abe45", "fa883b5c60573b9fe96e1b5c63f6fff0", "cdd7b45d6f84e8cc09cbe55a14ba07af", "c5ec5f7ceb5bb3374e1f304fa08e185a01ccb4987c2c7fe26f9cd75cfe2a67b924b01f1b48eaec10294c36dfa6146bd44ffb0ed46dd79c04e036ad555249a8f93d4b0d87b4c7b0cf5374e8eda86c720cf9d10979b33f22242f1279a494f33cead6bc9864ba81ce2c3ecef4cfc29bc2e9dada00ac4ff39cbe0df44cd8207da5a1431734c9c44b7fc721153f043b054342bea0c265f1e41ad492889bd319796558a398f7d84ad18423fca0142734c475401b48267dcabb939e2574b6ebd0f343fb72a123b92fae4bf5b0399520ff3e02f6e8443b368a322692807127cc9351df4d435fdc4d3d451036d3d3019ff6b2775e"),
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

    func testToDataConversion() throws {
        let randomBytes = (0..<16).map { _ in UInt8.random(in: UInt8.min...UInt8.max) }
        let dataIn = Data(randomBytes)
        let iv = try AES._CBC.IV(ivBytes: dataIn)
        let dataOut = Data(iv)
        XCTAssertEqual(dataIn, dataOut)
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
