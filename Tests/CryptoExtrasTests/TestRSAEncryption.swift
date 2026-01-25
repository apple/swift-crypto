//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) YEARS Apple Inc. and the SwiftCrypto project authors
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

final class TestRSAEncryption: XCTestCase {

    func test_wycheproofOAEPVectors() throws {
        try wycheproofTest(
            jsonName: "rsa_oaep_misc_test",
            testFunction: self.testOAEPGroup)
        try wycheproofTest(
            jsonName: "rsa_oaep_2048_sha1_mgf1sha1_test",
            testFunction: self.testOAEPGroup)
        try wycheproofTest(
            jsonName: "rsa_oaep_2048_sha256_mgf1sha256_test",
            testFunction: self.testOAEPGroup)
    }

    private func testOAEPGroup(_ group: RSAEncryptionOAEPTestGroup) throws {
        let derPrivKey: _RSA.Encryption.PrivateKey
        let pemPrivKey: _RSA.Encryption.PrivateKey

        if group.keysize < 2048 {
            derPrivKey = try _RSA.Encryption.PrivateKey(unsafeDERRepresentation: group.privateKeyDerBytes)
            pemPrivKey = try _RSA.Encryption.PrivateKey(unsafePEMRepresentation: group.privateKeyPem)
        } else {
            derPrivKey = try _RSA.Encryption.PrivateKey(derRepresentation: group.privateKeyDerBytes)
            pemPrivKey = try _RSA.Encryption.PrivateKey(pemRepresentation: group.privateKeyPem)
        }

        XCTAssertEqual(derPrivKey.derRepresentation, pemPrivKey.derRepresentation)
        XCTAssertEqual(derPrivKey.pemRepresentation, pemPrivKey.pemRepresentation)

        let derPubKey = derPrivKey.publicKey

        let padding: _RSA.Encryption.Padding
        if group.sha == "SHA-1", group.mgfSha == "SHA-1" {
            padding = .PKCS1_OAEP
        } else if group.sha == "SHA-256", group.mgfSha == "SHA-256" {
            padding = .PKCS1_OAEP_SHA256
        } else {
            // We currently only support SHA-1, SHA-256.
            return
        }

        for test in group.tests {
            guard test.label?.isEmpty ?? true else {
                // We currently have no support for OAEP labels.
                continue
            }
            let valid: Bool

            do {
                let decryptResult = try derPrivKey.decrypt(test.ciphertextBytes, padding: padding)
                let encryptResult = try derPubKey.encrypt(test.messageBytes, padding: padding)
                let decryptResult2 = try derPrivKey.decrypt(encryptResult, padding: padding)

                valid = (test.messageBytes == decryptResult && decryptResult2 == decryptResult)
            } catch {
                valid = false
            }

            XCTAssertEqual(valid, test.expectedValidity, "test number \(test.tcId) failed, expected \(test.result) but got \(valid)")
        }
    }

    func testConstructKeyFromRSANumbers() throws {
        /// Check we can successfully construct keys from known valid values from a test vector.
        for testVector in RFC9474TestVector.allValues {
            _ = try _RSA.Encryption.PrivateKey(
                n: Data(hexString: testVector.n),
                e: Data(hexString: testVector.e),
                d: Data(hexString: testVector.d),
                p: Data(hexString: testVector.p),
                q: Data(hexString: testVector.q)
            )
            _ = try _RSA.Encryption.PublicKey(
                n: Data(hexString: testVector.n),
                e: Data(hexString: testVector.e)
            )
        }
        /// Also check that we can provide each argument as a different `ContiguousBytes` type.
        /// NOTE: these calls use `try?` because they are guaranteed to fail; we're just checking these calls compile.
        let bytesValues: [any ContiguousBytes] = [Data(), [UInt8]()]
        _ = try? _RSA.Encryption.PrivateKey(
            n: bytesValues.randomElement()!,
            e: bytesValues.randomElement()!,
            d: bytesValues.randomElement()!,
            p: bytesValues.randomElement()!,
            q: bytesValues.randomElement()!
        )
        _ = try? _RSA.Encryption.PublicKey(
            n: bytesValues.randomElement()!,
            e: bytesValues.randomElement()!
        )
    }

    func testConstructAndUseKeyFromRSANumbersWhileRecoveringPrimes() throws {
        let data = Array("hello, world!".utf8)

        for testVector in RFC9474TestVector.allValues {
            let key = try _RSA.Encryption.PrivateKey._createFromNumbers(
                n: Data(hexString: testVector.n),
                e: Data(hexString: testVector.e),
                d: Data(hexString: testVector.d)
            )

            let encrypted = try key.publicKey.encrypt(data, padding: .PKCS1_OAEP_SHA256)
            let decrypted = try key.decrypt(encrypted, padding: .PKCS1_OAEP_SHA256)

            XCTAssertEqual(Data(data), decrypted)
        }
    }

    func testGetKeyPrimitives() throws {
        for testVector in RFC9474TestVector.allValues {
            let n = try Data(hexString: testVector.n)
            let e = try Data(hexString: testVector.e)

            let primitives = try _RSA.Encryption.PublicKey(n: n, e: e).getKeyPrimitives()
            XCTAssertEqual(primitives.modulus, n)
            XCTAssertEqual(primitives.publicExponent, e)
        }
    }

    func testMaximumEncryptSize() throws {
        let pemRepresentation1024 = """
            -----BEGIN PUBLIC KEY-----
            MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCTLbu1QZhtXWKCHOjavP5NUCwJ
            5DwjoMKGlEM/PQOMiY+wup8R1kCOHV6g+FvJ86laHJc0gqwFf1U51YxtQFy7cGV4
            W2zJeTkqadO2fvTCjbZU+Oa78iVtTynq5h4yRWrTmveyzInhdVpi075Ql2hpGuET
            H1qYVxqaDIJEHyETDQIDAQAB
            -----END PUBLIC KEY-----
            """
        let pubKey1024 = try _RSA.Encryption.PublicKey(unsafePEMRepresentation: pemRepresentation1024)
        XCTAssertEqual(86, pubKey1024.maximumEncryptSize(with: .PKCS1_OAEP))
        XCTAssertEqual(62, pubKey1024.maximumEncryptSize(with: .PKCS1_OAEP_SHA256))

        let pemRepresentation2048 = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx8IRKcs5FrHlWye2lfwc
            Hr0Pi8g5iZhGMOOwmyIVsNULAvUIGZlIw38NNqebH3eF6ZxPiSRpwPwIs6QRcH5/
            IwbHkUc0KdBbUwXDrLs0w00I7Flu5RP7IEfkOZdDGEWFY1pA3H1HaogxKFc5k3mM
            s7pW6oty1eP4O7aVa/Pp363Vba7EZ2nru9lz4Ta+JU8UIHbpoddMGikGEKHrQ/Ge
            n9RMNzSIy/e7TgTwC39GKn8fwN6VfcdNjvIhJrFNha/ORNArpzup7FUUauGLKt3a
            jgsIjrAPBp63+Sy7+aFVoGTvI7DCkZ/Wv3JCFRuTAdYOa0A1xiqhTb1pcypvrd2T
            ZQIDAQAB
            -----END PUBLIC KEY-----
            """
        let pubKey2048 = try _RSA.Encryption.PublicKey(pemRepresentation: pemRepresentation2048)
        XCTAssertEqual(214, pubKey2048.maximumEncryptSize(with: .PKCS1_OAEP))
        XCTAssertEqual(190, pubKey2048.maximumEncryptSize(with: .PKCS1_OAEP_SHA256))
    }

    func testPKCS1() throws {
        let pubKeyPEM = """
            -----BEGIN RSA PUBLIC KEY-----
            MIIBCgKCAQEAv6ElnElHGQO1BC5wsU/S01tHK8GbCnDLkxkS1259kOU250pEjOJa
            ceOGFnhYzE36KXmKTrGw3o1m5vgbQz88j7/tNjymAX990I3YdWTnGQYcypp8c4TD
            wHIj5Q3OHYXAC0KUHRBSKBeS+QJybrMI6SAQbFpHh9C3Q9W3WTtSAVqs8VveS4Jc
            j4a3K21MNeHgNfyxwn3KTrrNs/c0yOvWlwyfxYTdWLFVVp2hn6YVQUfo7twM4BCE
            Xz/6gR03NpqjVqKeyBmmMtDIy82+BzG4vd3jm02zwNvahsBy9b2NCOjq3y2ud72b
            Q4bYU9/r/ccApts5BIW8ASwmYSGSmE6MzwIDAQAB
            -----END RSA PUBLIC KEY-----
            """
        let privKeyPEM = """
            -----BEGIN PRIVATE KEY-----
            MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC/oSWcSUcZA7UE
            LnCxT9LTW0crwZsKcMuTGRLXbn2Q5TbnSkSM4lpx44YWeFjMTfopeYpOsbDejWbm
            +BtDPzyPv+02PKYBf33Qjdh1ZOcZBhzKmnxzhMPAciPlDc4dhcALQpQdEFIoF5L5
            AnJuswjpIBBsWkeH0LdD1bdZO1IBWqzxW95LglyPhrcrbUw14eA1/LHCfcpOus2z
            9zTI69aXDJ/FhN1YsVVWnaGfphVBR+ju3AzgEIRfP/qBHTc2mqNWop7IGaYy0MjL
            zb4HMbi93eObTbPA29qGwHL1vY0I6OrfLa53vZtDhthT3+v9xwCm2zkEhbwBLCZh
            IZKYTozPAgMBAAECggEAGncL9bCdFBRR/JjZUXOfvzbc9msPmXqIcvFEi+Ijj05I
            rdqw6vAb45yzmQjX4qdmRDIX6tRZg/LtYjqjsT7bg1LTVOk9V/mei537ZgMgc3FH
            qqd5Ro7wZfSdhnXIoIUnR6bTQ8xMPGM9FgzDdwxcz61w9zXkqRonJUQvxTAPHEaH
            SiNhRP8LUjzB0Y2ZYVXMWbs0nPPrSE+xuzjcGRX3lvz7nNOM1N4EyWto1RVJIlry
            4EV8RFczo3BjPXZFbtval76AGPmurDVqBdHpDN6IBZdhz4ZX/0fq8NR2p8/6S5VZ
            4Ylcth1S3HErcnG2UqT8rl/P3m9idTv4EZOg6HziyQKBgQDsmxaQCFTJnDwxSQR+
            4j9WsgDpSxvCdnUtMX9w77aw3EIdcHkhnX99jTvNkt3uwGAsVsx4x7ilj1eaZOfl
            soMIX1WBBx11yN4GOw173VmzC0LtaBGTh/2ollxuNoEqYxkuKLNxWxTGW0uc5TVA
            0hK2c6cF4eZ5sH07aIU6HIIknQKBgQDPVkeyxhF6lvgobLxFQOChOyLVcb1EymnU
            W1zF27HciA+0FuaiWTj69bKoR8d+ZIFtIzVvjo7MfoFRJvEZmDGy5+I8HhpSW6JQ
            NLdaRI5RGYxbEGmmC48icknXioZJ8JOXhbVuMyT4uLaN5D1M47ZYaq75dPM83fqZ
            BDc+izDdWwKBgQCJw5d0j9VGeni1va0nb/avNP/A1qG4LZ72jH6GtJysB+NbHtT4
            1KqZ4PU0MlKUpGCbEIMHxEpn47l/RUec/765zkCL2ye1IBreh93HBFApJuJ2NwUc
            4K66TapN5eB5XLAZp0ssMns7L4csOG00a9zHbTmP/ENlEXUpdSc1ecnxJQKBgFsJ
            n2G35mTVdREK7X/bBMbGmHzv/BMAbYd4tjuKQ4Z5l6uTgqE2W/aVe2S4X7f3mXy6
            QPRCvCC+Szm+x45dbTUI7CVJcnVHFvXwr7FK+NJTTXWOt1TZLngJhrLFeEFvCN83
            Lnq8qjcro7yZwvDH64DXFw0hdMv9C9O0Li2gIEyRAoGBAK+C7Stfm3vViV2YfByt
            MI73t2rN+t3ffnKsXZtGzWW1kxv4cueiAdeM7QwE2AaN7yKzsSMfsSXe+/r69wUR
            UPB8NcGLKWE/gJuIcitQx1HCbQZ3AplRK6xhjDVXG1A5SszQVx09hhq76JVBm0sJ
            DDYta1f+sEfAS750XLJ7A1h0
            -----END PRIVATE KEY-----
            """
        let pubKey = try _RSA.Encryption.PublicKey(pemRepresentation: pubKeyPEM)
        let privKey = try _RSA.Encryption.PrivateKey(pemRepresentation: privKeyPEM)
        let msgs = [
            // empty
            "",
            // short
            "467A8AFB-9165-484A-8377-B66BCACD774A",
            // example text
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla rutrum odio ut sem luctus, non finibus diam congue. Suspendisse nisl enim, placerat consectetur dolor non, mattis sollicitudin augue.",
            // max length
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla rutrum odio ut sem luctus, non finibus diam congue. Suspendisse nisl enim, placerat consectetur dolor non, mattis sollicitudin augue. Pellentesque a est eget enim efficitur volutpat ",
        ]
        for msg in msgs {
            let msgEnc = try pubKey.encrypt(msg.data(using: .utf8)!, padding: ._WEAK_AND_INSECURE_PKCS_V1_5)
            let msgDec = String(data: try privKey.decrypt(msgEnc, padding: ._WEAK_AND_INSECURE_PKCS_V1_5), encoding: .utf8)!
            XCTAssertEqual(msg, msgDec)
        }
    }
}

struct RSAEncryptionOAEPTestGroup: Codable {
    var privateKeyPem: String
    var privateKeyPkcs8: String
    var sha: String
    var tests: [RSAEncryptionTest]
    var mgfSha: String
    var keysize: Int

    var privateKeyDerBytes: Data {
        return try! Data(hexString: self.privateKeyPkcs8)
    }
}

struct RSAEncryptionTest: Codable {
    var tcId: Int
    var comment: String
    var msg: String
    var ct: String
    var result: String
    var flags: [String]
    var label: String?

    var messageBytes: Data {
        return try! Data(hexString: self.msg)
    }

    var ciphertextBytes: Data {
        return try! Data(hexString: self.ct)
    }

    var expectedValidity: Bool {
        switch self.result {
        case "valid":
            return true
        case "invalid":
            return false
        case "acceptable":
            return true
        default:
            fatalError("Unexpected validity")
        }
    }
}
