//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftCrypto project authors
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
@testable import Crypto
import _CryptoExtras

final class TestRSASigning: XCTestCase {
    func test_wycheproofPKCS1Vectors() throws {
        try wycheproofTest(
            jsonName: "rsa_signature_test",
            testFunction: self.testPKCS1Group)

        try wycheproofTest(
            jsonName: "rsa_signature_2048_sha256_test",
            testFunction: self.testPKCS1Group)

        try wycheproofTest(
            jsonName: "rsa_signature_2048_sha512_test",
            testFunction: self.testPKCS1Group)

        try wycheproofTest(
            jsonName: "rsa_signature_3072_sha256_test",
            testFunction: self.testPKCS1Group)

        try wycheproofTest(
            jsonName: "rsa_signature_3072_sha512_test",
            testFunction: self.testPKCS1Group)

        try wycheproofTest(
            jsonName: "rsa_signature_4096_sha512_test",
            testFunction: self.testPKCS1Group)
    }

    func test_wycheproofPSSVectors() throws {
        try wycheproofTest(
            jsonName: "rsa_pss_2048_sha1_mgf1_20_test",
            testFunction: self.testPSSGroup)

        try wycheproofTest(
            jsonName: "rsa_pss_2048_sha256_mgf1_0_test",
            testFunction: self.testPSSGroup)

        try wycheproofTest(
            jsonName: "rsa_pss_2048_sha256_mgf1_32_test",
            testFunction: self.testPSSGroup)

        try wycheproofTest(
            jsonName: "rsa_pss_3072_sha256_mgf1_32_test",
            testFunction: self.testPSSGroup)

        try wycheproofTest(
            jsonName: "rsa_pss_4096_sha256_mgf1_32_test",
            testFunction: self.testPSSGroup)

        try wycheproofTest(
            jsonName: "rsa_pss_4096_sha512_mgf1_32_test",
            testFunction: self.testPSSGroup)

        try wycheproofTest(
            jsonName: "rsa_pss_misc_test",
            testFunction: self.testPSSGroup)
    }

    func testPKCS1Signing() throws {
        try self.testPKCS1Signing(_RSA.Signing.PrivateKey(keySize: .bits2048))
        try self.testPKCS1Signing(_RSA.Signing.PrivateKey(keySize: .bits3072))
        try self.testPKCS1Signing(_RSA.Signing.PrivateKey(keySize: .bits4096))
    }

    private func testPKCS1Signing(_ key: _RSA.Signing.PrivateKey) throws {
        let test = Data("hello, world".utf8)

        // Test pre hashed.
        let preHashedSha256 = SHA256.hash(data: test)
        XCTAssertTrue(
            try key.publicKey.isValidSignature(
                key.signature(for: preHashedSha256, padding: .insecurePKCS1v1_5),
                for: preHashedSha256,
                padding: .insecurePKCS1v1_5
            )
        )

        // Test pre-hashed with other hash function
        let preHashedSha512 = SHA512.hash(data: test)
        XCTAssertTrue(
            try key.publicKey.isValidSignature(
                key.signature(for: preHashedSha512, padding: .insecurePKCS1v1_5),
                for: preHashedSha512,
                padding: .insecurePKCS1v1_5
            )
        )

        // Test unhashed
        XCTAssertTrue(
            try key.publicKey.isValidSignature(
                key.signature(for: test, padding: .insecurePKCS1v1_5),
                for: test,
                padding: .insecurePKCS1v1_5
            )
        )

        // Test unhashed corresponds to SHA256
        XCTAssertTrue(
            try key.publicKey.isValidSignature(
                key.signature(for: test, padding: .insecurePKCS1v1_5),
                for: preHashedSha256,
                padding: .insecurePKCS1v1_5
            )
        )
        XCTAssertTrue(
            try key.publicKey.isValidSignature(
                key.signature(for: preHashedSha256, padding: .insecurePKCS1v1_5),
                for: test,
                padding: .insecurePKCS1v1_5
            )
        )

        // Test unspecified padding does not imply PKCS1v1.5
        XCTAssertFalse(
            try key.publicKey.isValidSignature(
                key.signature(for: test),
                for: test,
                padding: .insecurePKCS1v1_5
            )
        )
        XCTAssertFalse(
            try key.publicKey.isValidSignature(
                key.signature(for: test, padding: .insecurePKCS1v1_5),
                for: test
            )
        )
    }

    func testPSSSigning() throws {
        try testPSSSigning(try _RSA.Signing.PrivateKey(keySize: .bits2048))
        try testPSSSigning(try _RSA.Signing.PrivateKey(keySize: .bits3072))
        try testPSSSigning(try _RSA.Signing.PrivateKey(keySize: .bits4096))
    }

    private func testPSSSigning(_ key: _RSA.Signing.PrivateKey) throws {
        let data = Data("hello, world".utf8)

        // Test pre hashed.
        func preHashedExplicitPaddingForBoth<DigestHash: HashFunction>(
            key: _RSA.Signing.PrivateKey, data: Data, hashFunction: DigestHash.Type = DigestHash.self
        ) throws {
            let preHashed = DigestHash.hash(data: data)
            XCTAssertTrue(
                try key.publicKey.isValidSignature(
                    key.signature(for: preHashed, padding: .PSS),
                    for: preHashed,
                    padding: .PSS
                )
            )
        }

        func preHashedImplicitPaddingForBoth<DigestHash: HashFunction>(
            key: _RSA.Signing.PrivateKey, data: Data, hashFunction: DigestHash.Type = DigestHash.self
        ) throws {
            let preHashed = DigestHash.hash(data: data)
            XCTAssertTrue(
                try key.publicKey.isValidSignature(
                    key.signature(for: preHashed),
                    for: preHashed
                )
            )
        }

        func unhashedExplicitPaddingForBoth(
            key: _RSA.Signing.PrivateKey, data: Data
        ) throws {
            XCTAssertTrue(
                try key.publicKey.isValidSignature(
                    key.signature(for: data, padding: .PSS),
                    for: data,
                    padding: .PSS
                )
            )
        }

        func unhashedIsSHA256ExplicitPadding(
            key: _RSA.Signing.PrivateKey, data: Data
        ) throws {
            let hashed = SHA256.hash(data: data)
            XCTAssertTrue(
                try key.publicKey.isValidSignature(
                    key.signature(for: data, padding: .PSS),
                    for: hashed,
                    padding: .PSS
                )
            )

            XCTAssertTrue(
                try key.publicKey.isValidSignature(
                    key.signature(for: hashed, padding: .PSS),
                    for: data,
                    padding: .PSS
                )
            )
        }

        func explicitHashingWithImplicitPaddingMatchesHashFunction<DigestHash: HashFunction>(
            key: _RSA.Signing.PrivateKey, data: Data, hashFunction: DigestHash.Type = DigestHash.self
        ) throws {
            let preHashed = DigestHash.hash(data: data)
            XCTAssertTrue(
                try key.publicKey.isValidSignature(
                    key.signature(for: preHashed),
                    for: preHashed,
                    padding: .PSS
                )
            )

            XCTAssertTrue(
                try key.publicKey.isValidSignature(
                    key.signature(for: preHashed, padding: .PSS),
                    for: preHashed
                )
            )
        }

        func implicitHashingWithImplicitPadding(
            key: _RSA.Signing.PrivateKey, data: Data
        ) throws {
            XCTAssertTrue(
                try key.publicKey.isValidSignature(
                    key.signature(for: data),
                    for: data,
                    padding: .PSS
                )
            )

            XCTAssertTrue(
                try key.publicKey.isValidSignature(
                    key.signature(for: data, padding: .PSS),
                    for: data
                )
            )
        }

        try preHashedExplicitPaddingForBoth(key: key, data: data, hashFunction: SHA256.self)
        try preHashedExplicitPaddingForBoth(key: key, data: data, hashFunction: SHA384.self)
        try preHashedExplicitPaddingForBoth(key: key, data: data, hashFunction: SHA512.self)
        try preHashedExplicitPaddingForBoth(key: key, data: data, hashFunction: Insecure.SHA1.self)

        try preHashedImplicitPaddingForBoth(key: key, data: data, hashFunction: SHA256.self)
        try preHashedImplicitPaddingForBoth(key: key, data: data, hashFunction: SHA384.self)
        try preHashedImplicitPaddingForBoth(key: key, data: data, hashFunction: SHA512.self)
        try preHashedImplicitPaddingForBoth(key: key, data: data, hashFunction: Insecure.SHA1.self)

        try unhashedExplicitPaddingForBoth(key: key, data: data)

        try unhashedIsSHA256ExplicitPadding(key: key, data: data)

        try explicitHashingWithImplicitPaddingMatchesHashFunction(key: key, data: data, hashFunction: SHA256.self)
        try explicitHashingWithImplicitPaddingMatchesHashFunction(key: key, data: data, hashFunction: SHA384.self)
        try explicitHashingWithImplicitPaddingMatchesHashFunction(key: key, data: data, hashFunction: SHA512.self)
        try explicitHashingWithImplicitPaddingMatchesHashFunction(key: key, data: data, hashFunction: Insecure.SHA1.self)

        try implicitHashingWithImplicitPadding(key: key, data: data)
    }

    func testSignatureSerialization() throws {
        let data = Array("hello, world!".utf8)
        let key = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let signature = try key.signature(for: data)
        let roundTripped = _RSA.Signing.RSASignature(rawRepresentation: signature.rawRepresentation)
        XCTAssertEqual(signature.rawRepresentation, roundTripped.rawRepresentation)
        XCTAssertTrue(key.publicKey.isValidSignature(roundTripped, for: data))
    }

    func testKeySizes() throws {
        let keysAndSizes: [(_RSA.Signing.PrivateKey, Int)] = try [
            (_RSA.Signing.PrivateKey(keySize: .bits2048), 2048),
            (_RSA.Signing.PrivateKey(keySize: .bits3072), 3072),
            (_RSA.Signing.PrivateKey(keySize: .bits4096), 4096),
            (_RSA.Signing.PrivateKey(keySize: .init(bitCount: 1024)), 1024),
        ]

        for (key, size) in keysAndSizes {
            XCTAssertEqual(size, key.keySizeInBits)
            XCTAssertEqual(size, key.publicKey.keySizeInBits)
        }
    }

    func testRejectSmallKeys() throws {
        let smallRSAPrivateKeyPEM = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIBPAIBAAJBAOJMTCxw5nMxXCQgsOIRVCu8z1t58s5r2qSqwpZQvQZLlVrhYTpE
        nHFD6QbX8lHkk1Z3HZ1vjxW89ARPh94cG+0CAwEAAQJBAMdmOVyTYswvuyPuVk3s
        vQEJDqFpFATFTlP4TxuKKvTmbdQuVCorMmLLKThDI3pDNWKuAvV+mqUDwk8lM0Tv
        ItUCIQD/p0sUPuATOc17qrebax6DQjAzfzzHr2iwZGX+uq27swIhAOKa0YoCvcJY
        sODBvtIS//8cE9r2mWDwPxp3yAKxunnfAiATrhgsfc6YDEoSLAkoUK2vowe83x2Z
        rZocgg4L9ujq2wIhAIIKCF9jzVO/I9oHNSNG5gOXMEnCpCg+Fmhw/qWVKocPAiEA
        jR4Tgjp6d5ZsGUK9IHGsNWP1ySrag7MWbrFpUouirbQ=
        -----END RSA PRIVATE KEY-----
        """

        let smallRSAPublicKeyPEM = """
        -----BEGIN PUBLIC KEY-----
        MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOJMTCxw5nMxXCQgsOIRVCu8z1t58s5r
        2qSqwpZQvQZLlVrhYTpEnHFD6QbX8lHkk1Z3HZ1vjxW89ARPh94cG+0CAwEAAQ==
        -----END PUBLIC KEY-----
        """

        let smallRSAPrivateKeyPKCS8PEM = """
        -----BEGIN PRIVATE KEY-----
        MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEA4kxMLHDmczFcJCCw
        4hFUK7zPW3nyzmvapKrCllC9BkuVWuFhOkSccUPpBtfyUeSTVncdnW+PFbz0BE+H
        3hwb7QIDAQABAkEAx2Y5XJNizC+7I+5WTey9AQkOoWkUBMVOU/hPG4oq9OZt1C5U
        KisyYsspOEMjekM1Yq4C9X6apQPCTyUzRO8i1QIhAP+nSxQ+4BM5zXuqt5trHoNC
        MDN/PMevaLBkZf66rbuzAiEA4prRigK9wliw4MG+0hL//xwT2vaZYPA/GnfIArG6
        ed8CIBOuGCx9zpgMShIsCShQra+jB7zfHZmtmhyCDgv26OrbAiEAggoIX2PNU78j
        2gc1I0bmA5cwScKkKD4WaHD+pZUqhw8CIQCNHhOCOnp3lmwZQr0gcaw1Y/XJKtqD
        sxZusWlSi6KttA==
        -----END PRIVATE KEY-----
        """

        let smallRSAPrivateKeyDER = Data(base64Encoded:
            "MIIBPAIBAAJBAOJMTCxw5nMxXCQgsOIRVCu8z1t58s5r2qSqwpZQvQZLlVr" +
            "hYTpEnHFD6QbX8lHkk1Z3HZ1vjxW89ARPh94cG+0CAwEAAQJBAMdmOVyTYs" +
            "wvuyPuVk3svQEJDqFpFATFTlP4TxuKKvTmbdQuVCorMmLLKThDI3pDNWKuA" +
            "vV+mqUDwk8lM0TvItUCIQD/p0sUPuATOc17qrebax6DQjAzfzzHr2iwZGX+" +
            "uq27swIhAOKa0YoCvcJYsODBvtIS//8cE9r2mWDwPxp3yAKxunnfAiATrhg" +
            "sfc6YDEoSLAkoUK2vowe83x2ZrZocgg4L9ujq2wIhAIIKCF9jzVO/I9oHNS" +
            "NG5gOXMEnCpCg+Fmhw/qWVKocPAiEAjR4Tgjp6d5ZsGUK9IHGsNWP1ySrag" +
            "7MWbrFpUouirbQ="
        )!

        let smallRSAPrivateKeyPKCS8DER = Data(base64Encoded:
            "MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEA4kxMLHDmczF" +
            "cJCCw4hFUK7zPW3nyzmvapKrCllC9BkuVWuFhOkSccUPpBtfyUeSTVncdnW" +
            "+PFbz0BE+H3hwb7QIDAQABAkEAx2Y5XJNizC+7I+5WTey9AQkOoWkUBMVOU" +
            "/hPG4oq9OZt1C5UKisyYsspOEMjekM1Yq4C9X6apQPCTyUzRO8i1QIhAP+n" +
            "SxQ+4BM5zXuqt5trHoNCMDN/PMevaLBkZf66rbuzAiEA4prRigK9wliw4MG" +
            "+0hL//xwT2vaZYPA/GnfIArG6ed8CIBOuGCx9zpgMShIsCShQra+jB7zfHZ" +
            "mtmhyCDgv26OrbAiEAggoIX2PNU78j2gc1I0bmA5cwScKkKD4WaHD+pZUqh" +
            "w8CIQCNHhOCOnp3lmwZQr0gcaw1Y/XJKtqDsxZusWlSi6KttA=="
        )!

        let smallRSAPublicKeyDER = Data(base64Encoded:
            "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOJMTCxw5nMxXCQgsOIRVCu8z1t" +
            "58s5r2qSqwpZQvQZLlVrhYTpEnHFD6QbX8lHkk1Z3HZ1vjxW89ARPh94cG+" +
            "0CAwEAAQ=="
        )!

        XCTAssertThrowsError(try _RSA.Signing.PrivateKey(pemRepresentation: smallRSAPrivateKeyPEM))
        XCTAssertThrowsError(try _RSA.Signing.PrivateKey(pemRepresentation: smallRSAPrivateKeyPKCS8PEM))
        XCTAssertThrowsError(try _RSA.Signing.PrivateKey(derRepresentation: smallRSAPrivateKeyDER))
        XCTAssertThrowsError(try _RSA.Signing.PrivateKey(derRepresentation: smallRSAPrivateKeyPKCS8DER))
        XCTAssertThrowsError(try _RSA.Signing.PublicKey(pemRepresentation: smallRSAPublicKeyPEM))
        XCTAssertThrowsError(try _RSA.Signing.PublicKey(derRepresentation: smallRSAPublicKeyDER))
    }

    func testHandlingNonStandardKeys() throws {
        let awkwardRSAPrivateKeyPEM = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQECxVSlteS7/eN5dXzn+RdyApV8JJILQaXaZOgxl/FELWhXq4lY
        Uk6+0keFtdLvSsdsBAZlq7VT8vHyfxqhcpb0RkjThWfVhR2BjzO8TNLA+mlKGKZJ
        foTE3r7o99Ev4X+H4QxCyAC8oyAKy1lyDA4wT7OFBBXtXJmeQ/PbYCuMMyqrCWUg
        VL48rK150QxHQ0U9XsGCnF70X/PMPebKY60OS36pTYhmi77h0maiY4yW2kHNfgeG
        Mbc3XQ19Sr42f5zKe0AIQfzK91v6M5PaEIpJAfm+JPDNWf2+RKEVa93gNiuTZ2+p
        gUjf7ut8mY5MEn7fZhCeZeNBjNTuKXj3JqdP3wIDAQABAoIBAQC252vPakq7XeOc
        0vdx+ISye99GAs6aP+z/pgvbtR+yYbxxg/ndR2bXDBBDYT/I1YFZzFh9HUWnWJIC
        CljlFl2onfDE7pBVQdV9moaMfK+8Ilgz4PUEhbHKCgpClJM3H05nTmUN83qwyXtf
        EhJhX2s/sfezpP/Op+HyfbfspW4CZrrJmv1zfqIjDiV7LMaoDDU+UDHexcgwoXCa
        HKC/U7RcbNYE3hOg/Fjx+nevprXthhf8mpnkAzTcpXsMcATuvh7sSqdFnHkF9egw
        CBnlx+iH9J/6Q3VwoZgwggi9S6qT5yrS0/JVWVic4KaiE81dDr+KLmXIpOFRNuYf
        8sP79cfRAoGBAcwBZ+XfX5H8Ii7tSjCJWJ+sw6cevH4YQhYWDEgodsmzj2hDRoRj
        EaGdATP5dry7RWePTuhN0KlvMYX/xI2kvoRrK6sR4bad0V2J8lKBFxAil55w531L
        wZUAhxzAChWZ6uRMR694yati/8wIG+BMdwBPA+00+pMH2Kd9HGN8xoBHAoGBAYrA
        0sfOCNqvkf7OsoiShjSdeTYkTqjHrVR7m6DJg2FUL6E9VnaSLG0esnAYGAozKfFl
        rQz7gEGckMG2dILOAY9z3wv4ltX12RxmAJMHoO/ENDVxiqSKC7utiKzcii9qy626
        RIuAvOwSOeU25VVTOzOm35wabuLAThMYBqdYl9epAoGAYsWKgZlM9BOnY1wgKfvT
        w7Vc7W10G78psYRabsQBfZ3IlSKc6aA8EO+daoOOM0gixvHGh6rtuvPdNmCM270c
        C2LXpYvZY1TPt73/Aiglw5kp5SNpEUZK8quCV3IEuE6sWQjn+418AAjp0+2Jzsec
        ZbyRo0VU6G0u4AfFKLeKB9ECgYAURk8NIBHoWXggJDGbPhtSfHwLQdYgaREH88lM
        es0apJ5Fo8bbFCrf9+GmTDZ/35zZ3yUCM7CkrgvpRxu41CfUXFkqXjwxBQ1/neWN
        p6imZ+dej1RVmxl7LDCG4FTglpWbeKOonpYVceIzWZxxw3KY9ospk1n6n3HjHSrK
        UYyK8QKBgQDWsxq+0VhPgMRDUKg2p1gdnluX9I5lmZVwy1No6QfChJUo/RCRYcIe
        jLXlpoAW9UUR5JCx3/hKyKvbl34J/LV3Tc/63vHxOGnh8eAySyCcpFJFmyciIZdY
        iRLB6wzq+zLIZkK7+5TdHCZ9jIi5oKyk2YDT6LSTUnuG9DlGpcSmqA==
        -----END RSA PRIVATE KEY-----
        """

        let awkwardRSAPublicKeyPEM = """
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQECxVSlteS7/eN5dXzn+Rdy
        ApV8JJILQaXaZOgxl/FELWhXq4lYUk6+0keFtdLvSsdsBAZlq7VT8vHyfxqhcpb0
        RkjThWfVhR2BjzO8TNLA+mlKGKZJfoTE3r7o99Ev4X+H4QxCyAC8oyAKy1lyDA4w
        T7OFBBXtXJmeQ/PbYCuMMyqrCWUgVL48rK150QxHQ0U9XsGCnF70X/PMPebKY60O
        S36pTYhmi77h0maiY4yW2kHNfgeGMbc3XQ19Sr42f5zKe0AIQfzK91v6M5PaEIpJ
        Afm+JPDNWf2+RKEVa93gNiuTZ2+pgUjf7ut8mY5MEn7fZhCeZeNBjNTuKXj3JqdP
        3wIDAQAB
        -----END PUBLIC KEY-----
        """

        let awkwardRSAPrivateKeyPKCS8PEM = """
        -----BEGIN PRIVATE KEY-----
        MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQLFVKW15Lv943l1
        fOf5F3IClXwkkgtBpdpk6DGX8UQtaFeriVhSTr7SR4W10u9Kx2wEBmWrtVPy8fJ/
        GqFylvRGSNOFZ9WFHYGPM7xM0sD6aUoYpkl+hMTevuj30S/hf4fhDELIALyjIArL
        WXIMDjBPs4UEFe1cmZ5D89tgK4wzKqsJZSBUvjysrXnRDEdDRT1ewYKcXvRf88w9
        5spjrQ5LfqlNiGaLvuHSZqJjjJbaQc1+B4YxtzddDX1KvjZ/nMp7QAhB/Mr3W/oz
        k9oQikkB+b4k8M1Z/b5EoRVr3eA2K5Nnb6mBSN/u63yZjkwSft9mEJ5l40GM1O4p
        ePcmp0/fAgMBAAECggEBALbna89qSrtd45zS93H4hLJ730YCzpo/7P+mC9u1H7Jh
        vHGD+d1HZtcMEENhP8jVgVnMWH0dRadYkgIKWOUWXaid8MTukFVB1X2ahox8r7wi
        WDPg9QSFscoKCkKUkzcfTmdOZQ3zerDJe18SEmFfaz+x97Ok/86n4fJ9t+ylbgJm
        usma/XN+oiMOJXssxqgMNT5QMd7FyDChcJocoL9TtFxs1gTeE6D8WPH6d6+mte2G
        F/yameQDNNylewxwBO6+HuxKp0WceQX16DAIGeXH6If0n/pDdXChmDCCCL1LqpPn
        KtLT8lVZWJzgpqITzV0Ov4ouZcik4VE25h/yw/v1x9ECgYEBzAFn5d9fkfwiLu1K
        MIlYn6zDpx68fhhCFhYMSCh2ybOPaENGhGMRoZ0BM/l2vLtFZ49O6E3QqW8xhf/E
        jaS+hGsrqxHhtp3RXYnyUoEXECKXnnDnfUvBlQCHHMAKFZnq5ExHr3jJq2L/zAgb
        4Ex3AE8D7TT6kwfYp30cY3zGgEcCgYEBisDSx84I2q+R/s6yiJKGNJ15NiROqMet
        VHuboMmDYVQvoT1WdpIsbR6ycBgYCjMp8WWtDPuAQZyQwbZ0gs4Bj3PfC/iW1fXZ
        HGYAkweg78Q0NXGKpIoLu62IrNyKL2rLrbpEi4C87BI55TblVVM7M6bfnBpu4sBO
        ExgGp1iX16kCgYBixYqBmUz0E6djXCAp+9PDtVztbXQbvymxhFpuxAF9nciVIpzp
        oDwQ751qg44zSCLG8caHqu268902YIzbvRwLYteli9ljVM+3vf8CKCXDmSnlI2kR
        Rkryq4JXcgS4TqxZCOf7jXwACOnT7YnOx5xlvJGjRVTobS7gB8Uot4oH0QKBgBRG
        Tw0gEehZeCAkMZs+G1J8fAtB1iBpEQfzyUx6zRqknkWjxtsUKt/34aZMNn/fnNnf
        JQIzsKSuC+lHG7jUJ9RcWSpePDEFDX+d5Y2nqKZn516PVFWbGXssMIbgVOCWlZt4
        o6ielhVx4jNZnHHDcpj2iymTWfqfceMdKspRjIrxAoGBANazGr7RWE+AxENQqDan
        WB2eW5f0jmWZlXDLU2jpB8KElSj9EJFhwh6MteWmgBb1RRHkkLHf+ErIq9uXfgn8
        tXdNz/re8fE4aeHx4DJLIJykUkWbJyIhl1iJEsHrDOr7MshmQrv7lN0cJn2MiLmg
        rKTZgNPotJNSe4b0OUalxKao
        -----END PRIVATE KEY-----
        """

        let awkwardRSAPrivateKeyDER = Data(base64Encoded:
            "MIIEpAIBAAKCAQECxVSlteS7/eN5dXzn+RdyApV8JJILQaXaZOgxl/FELWh" +
            "Xq4lYUk6+0keFtdLvSsdsBAZlq7VT8vHyfxqhcpb0RkjThWfVhR2BjzO8TN" +
            "LA+mlKGKZJfoTE3r7o99Ev4X+H4QxCyAC8oyAKy1lyDA4wT7OFBBXtXJmeQ" +
            "/PbYCuMMyqrCWUgVL48rK150QxHQ0U9XsGCnF70X/PMPebKY60OS36pTYhm" +
            "i77h0maiY4yW2kHNfgeGMbc3XQ19Sr42f5zKe0AIQfzK91v6M5PaEIpJAfm" +
            "+JPDNWf2+RKEVa93gNiuTZ2+pgUjf7ut8mY5MEn7fZhCeZeNBjNTuKXj3Jq" +
            "dP3wIDAQABAoIBAQC252vPakq7XeOc0vdx+ISye99GAs6aP+z/pgvbtR+yY" +
            "bxxg/ndR2bXDBBDYT/I1YFZzFh9HUWnWJICCljlFl2onfDE7pBVQdV9moaM" +
            "fK+8Ilgz4PUEhbHKCgpClJM3H05nTmUN83qwyXtfEhJhX2s/sfezpP/Op+H" +
            "yfbfspW4CZrrJmv1zfqIjDiV7LMaoDDU+UDHexcgwoXCaHKC/U7RcbNYE3h" +
            "Og/Fjx+nevprXthhf8mpnkAzTcpXsMcATuvh7sSqdFnHkF9egwCBnlx+iH9" +
            "J/6Q3VwoZgwggi9S6qT5yrS0/JVWVic4KaiE81dDr+KLmXIpOFRNuYf8sP7" +
            "9cfRAoGBAcwBZ+XfX5H8Ii7tSjCJWJ+sw6cevH4YQhYWDEgodsmzj2hDRoR" +
            "jEaGdATP5dry7RWePTuhN0KlvMYX/xI2kvoRrK6sR4bad0V2J8lKBFxAil5" +
            "5w531LwZUAhxzAChWZ6uRMR694yati/8wIG+BMdwBPA+00+pMH2Kd9HGN8x" +
            "oBHAoGBAYrA0sfOCNqvkf7OsoiShjSdeTYkTqjHrVR7m6DJg2FUL6E9VnaS" +
            "LG0esnAYGAozKfFlrQz7gEGckMG2dILOAY9z3wv4ltX12RxmAJMHoO/ENDV" +
            "xiqSKC7utiKzcii9qy626RIuAvOwSOeU25VVTOzOm35wabuLAThMYBqdYl9" +
            "epAoGAYsWKgZlM9BOnY1wgKfvTw7Vc7W10G78psYRabsQBfZ3IlSKc6aA8E" +
            "O+daoOOM0gixvHGh6rtuvPdNmCM270cC2LXpYvZY1TPt73/Aiglw5kp5SNp" +
            "EUZK8quCV3IEuE6sWQjn+418AAjp0+2JzsecZbyRo0VU6G0u4AfFKLeKB9E" +
            "CgYAURk8NIBHoWXggJDGbPhtSfHwLQdYgaREH88lMes0apJ5Fo8bbFCrf9+" +
            "GmTDZ/35zZ3yUCM7CkrgvpRxu41CfUXFkqXjwxBQ1/neWNp6imZ+dej1RVm" +
            "xl7LDCG4FTglpWbeKOonpYVceIzWZxxw3KY9ospk1n6n3HjHSrKUYyK8QKB" +
            "gQDWsxq+0VhPgMRDUKg2p1gdnluX9I5lmZVwy1No6QfChJUo/RCRYcIejLX" +
            "lpoAW9UUR5JCx3/hKyKvbl34J/LV3Tc/63vHxOGnh8eAySyCcpFJFmyciIZ" +
            "dYiRLB6wzq+zLIZkK7+5TdHCZ9jIi5oKyk2YDT6LSTUnuG9DlGpcSmqA=="
        )!

        let awkwardRSAPrivateKeyPKCS8DER = Data(base64Encoded:
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQLFVKW15Lv" +
            "943l1fOf5F3IClXwkkgtBpdpk6DGX8UQtaFeriVhSTr7SR4W10u9Kx2wEBm" +
            "WrtVPy8fJ/GqFylvRGSNOFZ9WFHYGPM7xM0sD6aUoYpkl+hMTevuj30S/hf" +
            "4fhDELIALyjIArLWXIMDjBPs4UEFe1cmZ5D89tgK4wzKqsJZSBUvjysrXnR" +
            "DEdDRT1ewYKcXvRf88w95spjrQ5LfqlNiGaLvuHSZqJjjJbaQc1+B4Yxtzd" +
            "dDX1KvjZ/nMp7QAhB/Mr3W/ozk9oQikkB+b4k8M1Z/b5EoRVr3eA2K5Nnb6" +
            "mBSN/u63yZjkwSft9mEJ5l40GM1O4pePcmp0/fAgMBAAECggEBALbna89qS" +
            "rtd45zS93H4hLJ730YCzpo/7P+mC9u1H7JhvHGD+d1HZtcMEENhP8jVgVnM" +
            "WH0dRadYkgIKWOUWXaid8MTukFVB1X2ahox8r7wiWDPg9QSFscoKCkKUkzc" +
            "fTmdOZQ3zerDJe18SEmFfaz+x97Ok/86n4fJ9t+ylbgJmusma/XN+oiMOJX" +
            "ssxqgMNT5QMd7FyDChcJocoL9TtFxs1gTeE6D8WPH6d6+mte2GF/yameQDN" +
            "NylewxwBO6+HuxKp0WceQX16DAIGeXH6If0n/pDdXChmDCCCL1LqpPnKtLT" +
            "8lVZWJzgpqITzV0Ov4ouZcik4VE25h/yw/v1x9ECgYEBzAFn5d9fkfwiLu1" +
            "KMIlYn6zDpx68fhhCFhYMSCh2ybOPaENGhGMRoZ0BM/l2vLtFZ49O6E3QqW" +
            "8xhf/EjaS+hGsrqxHhtp3RXYnyUoEXECKXnnDnfUvBlQCHHMAKFZnq5ExHr" +
            "3jJq2L/zAgb4Ex3AE8D7TT6kwfYp30cY3zGgEcCgYEBisDSx84I2q+R/s6y" +
            "iJKGNJ15NiROqMetVHuboMmDYVQvoT1WdpIsbR6ycBgYCjMp8WWtDPuAQZy" +
            "QwbZ0gs4Bj3PfC/iW1fXZHGYAkweg78Q0NXGKpIoLu62IrNyKL2rLrbpEi4" +
            "C87BI55TblVVM7M6bfnBpu4sBOExgGp1iX16kCgYBixYqBmUz0E6djXCAp+" +
            "9PDtVztbXQbvymxhFpuxAF9nciVIpzpoDwQ751qg44zSCLG8caHqu268902" +
            "YIzbvRwLYteli9ljVM+3vf8CKCXDmSnlI2kRRkryq4JXcgS4TqxZCOf7jXw" +
            "ACOnT7YnOx5xlvJGjRVTobS7gB8Uot4oH0QKBgBRGTw0gEehZeCAkMZs+G1" +
            "J8fAtB1iBpEQfzyUx6zRqknkWjxtsUKt/34aZMNn/fnNnfJQIzsKSuC+lHG" +
            "7jUJ9RcWSpePDEFDX+d5Y2nqKZn516PVFWbGXssMIbgVOCWlZt4o6ielhVx" +
            "4jNZnHHDcpj2iymTWfqfceMdKspRjIrxAoGBANazGr7RWE+AxENQqDanWB2" +
            "eW5f0jmWZlXDLU2jpB8KElSj9EJFhwh6MteWmgBb1RRHkkLHf+ErIq9uXfg" +
            "n8tXdNz/re8fE4aeHx4DJLIJykUkWbJyIhl1iJEsHrDOr7MshmQrv7lN0cJ" +
            "n2MiLmgrKTZgNPotJNSe4b0OUalxKao"
        )!

        let awkwardRSAPublicKeyDER = Data(base64Encoded:
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQECxVSlteS7/eN5dXzn" +
            "+RdyApV8JJILQaXaZOgxl/FELWhXq4lYUk6+0keFtdLvSsdsBAZlq7VT8vHy" +
            "fxqhcpb0RkjThWfVhR2BjzO8TNLA+mlKGKZJfoTE3r7o99Ev4X+H4QxCyAC8" +
            "oyAKy1lyDA4wT7OFBBXtXJmeQ/PbYCuMMyqrCWUgVL48rK150QxHQ0U9XsGC" +
            "nF70X/PMPebKY60OS36pTYhmi77h0maiY4yW2kHNfgeGMbc3XQ19Sr42f5zK" +
            "e0AIQfzK91v6M5PaEIpJAfm+JPDNWf2+RKEVa93gNiuTZ2+pgUjf7ut8mY5M" +
            "En7fZhCeZeNBjNTuKXj3JqdP3wIDAQAB"
        )!

        XCTAssertEqual(try _RSA.Signing.PrivateKey(pemRepresentation: awkwardRSAPrivateKeyPEM).keySizeInBits, 2056)
        XCTAssertEqual(try _RSA.Signing.PrivateKey(pemRepresentation: awkwardRSAPrivateKeyPKCS8PEM).keySizeInBits, 2056)
        XCTAssertEqual(try _RSA.Signing.PrivateKey(derRepresentation: awkwardRSAPrivateKeyDER).keySizeInBits, 2056)
        XCTAssertEqual(try _RSA.Signing.PrivateKey(derRepresentation: awkwardRSAPrivateKeyPKCS8DER).keySizeInBits, 2056)
        XCTAssertEqual(try _RSA.Signing.PublicKey(pemRepresentation: awkwardRSAPublicKeyPEM).keySizeInBits, 2056)
        XCTAssertEqual(try _RSA.Signing.PublicKey(derRepresentation: awkwardRSAPublicKeyDER).keySizeInBits, 2056)
    }

    func testMangledPKCS8DERKey() throws {
        // The first 26 bytes of a PKCS8 key are structural. This test confirms that we validate them on all
        // codebases by flipping bits in them.
        let awkwardRSAPrivateKeyPKCS8DER = Data(base64Encoded:
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQLFVKW15Lv" +
            "943l1fOf5F3IClXwkkgtBpdpk6DGX8UQtaFeriVhSTr7SR4W10u9Kx2wEBm" +
            "WrtVPy8fJ/GqFylvRGSNOFZ9WFHYGPM7xM0sD6aUoYpkl+hMTevuj30S/hf" +
            "4fhDELIALyjIArLWXIMDjBPs4UEFe1cmZ5D89tgK4wzKqsJZSBUvjysrXnR" +
            "DEdDRT1ewYKcXvRf88w95spjrQ5LfqlNiGaLvuHSZqJjjJbaQc1+B4Yxtzd" +
            "dDX1KvjZ/nMp7QAhB/Mr3W/ozk9oQikkB+b4k8M1Z/b5EoRVr3eA2K5Nnb6" +
            "mBSN/u63yZjkwSft9mEJ5l40GM1O4pePcmp0/fAgMBAAECggEBALbna89qS" +
            "rtd45zS93H4hLJ730YCzpo/7P+mC9u1H7JhvHGD+d1HZtcMEENhP8jVgVnM" +
            "WH0dRadYkgIKWOUWXaid8MTukFVB1X2ahox8r7wiWDPg9QSFscoKCkKUkzc" +
            "fTmdOZQ3zerDJe18SEmFfaz+x97Ok/86n4fJ9t+ylbgJmusma/XN+oiMOJX" +
            "ssxqgMNT5QMd7FyDChcJocoL9TtFxs1gTeE6D8WPH6d6+mte2GF/yameQDN" +
            "NylewxwBO6+HuxKp0WceQX16DAIGeXH6If0n/pDdXChmDCCCL1LqpPnKtLT" +
            "8lVZWJzgpqITzV0Ov4ouZcik4VE25h/yw/v1x9ECgYEBzAFn5d9fkfwiLu1" +
            "KMIlYn6zDpx68fhhCFhYMSCh2ybOPaENGhGMRoZ0BM/l2vLtFZ49O6E3QqW" +
            "8xhf/EjaS+hGsrqxHhtp3RXYnyUoEXECKXnnDnfUvBlQCHHMAKFZnq5ExHr" +
            "3jJq2L/zAgb4Ex3AE8D7TT6kwfYp30cY3zGgEcCgYEBisDSx84I2q+R/s6y" +
            "iJKGNJ15NiROqMetVHuboMmDYVQvoT1WdpIsbR6ycBgYCjMp8WWtDPuAQZy" +
            "QwbZ0gs4Bj3PfC/iW1fXZHGYAkweg78Q0NXGKpIoLu62IrNyKL2rLrbpEi4" +
            "C87BI55TblVVM7M6bfnBpu4sBOExgGp1iX16kCgYBixYqBmUz0E6djXCAp+" +
            "9PDtVztbXQbvymxhFpuxAF9nciVIpzpoDwQ751qg44zSCLG8caHqu268902" +
            "YIzbvRwLYteli9ljVM+3vf8CKCXDmSnlI2kRRkryq4JXcgS4TqxZCOf7jXw" +
            "ACOnT7YnOx5xlvJGjRVTobS7gB8Uot4oH0QKBgBRGTw0gEehZeCAkMZs+G1" +
            "J8fAtB1iBpEQfzyUx6zRqknkWjxtsUKt/34aZMNn/fnNnfJQIzsKSuC+lHG" +
            "7jUJ9RcWSpePDEFDX+d5Y2nqKZn516PVFWbGXssMIbgVOCWlZt4o6ielhVx" +
            "4jNZnHHDcpj2iymTWfqfceMdKspRjIrxAoGBANazGr7RWE+AxENQqDanWB2" +
            "eW5f0jmWZlXDLU2jpB8KElSj9EJFhwh6MteWmgBb1RRHkkLHf+ErIq9uXfg" +
            "n8tXdNz/re8fE4aeHx4DJLIJykUkWbJyIhl1iJEsHrDOr7MshmQrv7lN0cJ" +
            "n2MiLmgrKTZgNPotJNSe4b0OUalxKao"
        )!

        // We must have at least one bit set.
        let bitFlipPattern = UInt8.random(in: 1...255)

        for offset in 0..<26 {
            var flipped = awkwardRSAPrivateKeyPKCS8DER
            flipped[offset] ^= bitFlipPattern

            XCTAssertThrowsError(try _RSA.Signing.PrivateKey(derRepresentation: flipped))

            let pemFlipped = pemForDERBytes(discriminator: "PRIVATE KEY", derBytes: flipped)
            XCTAssertThrowsError(try _RSA.Signing.PrivateKey(pemRepresentation: pemFlipped))
        }
    }

    func testRefuseToConstructSmallKeys() throws {
        XCTAssertThrowsError(try _RSA.Signing.PrivateKey(keySize: .init(bitCount: 1016)))
    }

    func testParsingPKCS1PublicKeyDER() throws {
        let pkcs1Key = Data(base64Encoded:
            "MIICCgKCAgEAkehUktIKVrGsDSTdxc9EZ3SZKzejfSNwAHG8U9/E+ioSj0t" +
            "/EFa9n3Byt2F/yUsPF6c947AEYe7/EZfH9IY+Cvo+XPmT5jR62RRr55yzha" +
            "CCenavcZDX7P0N+pxs+t+wgvQUfvm+xKYvT3+Zf7X8Z0NyvQwA1onrayzT7" +
            "Y+YHBSrfuXjbvzYqOSSJNpDa2K4Vf3qwbxstovzDo2a5JtsaZn4eEgwRdWt" +
            "4Q08RWD8MpZRJ7xnw8outmvqRsfHIKCxH2XeSAi6pE6p8oNGN4Tr6MyBSEN" +
            "nTnIqm1y9TBsoilwie7SrmNnu4FGDwwlGTm0+mfqVF9p8M1dBPI1R7Qu2XK" +
            "8sYxrfV8g/vOldxJuvRZnio1oktLqpVj3Pb6r/SVi+8Kj/9Lit6Tf7urj0C" +
            "zr56ENCHonYhMsT8dm74YlguIwoVqwUHZwK53Hrzw7dPamWoUi9PPevtQ0i" +
            "TMARgexWO/bTouJbt7IEIlKVgJNp6I5MZfGRAy1wdALqi2cVKWlSArvX31B" +
            "qVUa/oKMoYX9w0MOiqiwhqkfOKJwGRXa/ghgntNWutMtQ5mv0TIZxMOmm3x" +
            "aG4Nj/QN370EKIf6MzOi5cHkERgWPOGHFrK+ymircxXDpqR+DDeVnWIBqv8" +
            "mqYqnK8V0rSS527EPywTEHl7R09XiidnMy/s1Hap0flhFMCAwEAAQ=="
        )!
        let key = try _RSA.Signing.PublicKey(derRepresentation: pkcs1Key)
        XCTAssertEqual(pkcs1Key, key.pkcs1DERRepresentation)
    }

    func testParsingPKCS1PublicKeyPEM() throws {
        let pemKey = """
        -----BEGIN RSA PUBLIC KEY-----
        MIICCgKCAgEAkehUktIKVrGsDSTdxc9EZ3SZKzejfSNwAHG8U9/E+ioSj0t/EFa9
        n3Byt2F/yUsPF6c947AEYe7/EZfH9IY+Cvo+XPmT5jR62RRr55yzhaCCenavcZDX
        7P0N+pxs+t+wgvQUfvm+xKYvT3+Zf7X8Z0NyvQwA1onrayzT7Y+YHBSrfuXjbvzY
        qOSSJNpDa2K4Vf3qwbxstovzDo2a5JtsaZn4eEgwRdWt4Q08RWD8MpZRJ7xnw8ou
        tmvqRsfHIKCxH2XeSAi6pE6p8oNGN4Tr6MyBSENnTnIqm1y9TBsoilwie7SrmNnu
        4FGDwwlGTm0+mfqVF9p8M1dBPI1R7Qu2XK8sYxrfV8g/vOldxJuvRZnio1oktLqp
        Vj3Pb6r/SVi+8Kj/9Lit6Tf7urj0Czr56ENCHonYhMsT8dm74YlguIwoVqwUHZwK
        53Hrzw7dPamWoUi9PPevtQ0iTMARgexWO/bTouJbt7IEIlKVgJNp6I5MZfGRAy1w
        dALqi2cVKWlSArvX31BqVUa/oKMoYX9w0MOiqiwhqkfOKJwGRXa/ghgntNWutMtQ
        5mv0TIZxMOmm3xaG4Nj/QN370EKIf6MzOi5cHkERgWPOGHFrK+ymircxXDpqR+DD
        eVnWIBqv8mqYqnK8V0rSS527EPywTEHl7R09XiidnMy/s1Hap0flhFMCAwEAAQ==
        -----END RSA PUBLIC KEY-----
        """
        let key = try _RSA.Signing.PublicKey(pemRepresentation: pemKey)
        XCTAssertEqual(pemKey, key.pkcs1PEMRepresentation)
    }

    func testParsingSPKIPublicKeyDER() throws {
        let derKey = Data(base64Encoded:
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA509zjqylvktpuN3zMpdw" +
        "YwsZ2dp9/cJZ2Krp2EqK+UvMJcp4T3O9rWPMZk1RocQWLpfSwF8jtfyy1OHDQEZh" +
        "7UkpnlHmCwlNzzCj+/eaC+JP2Dy6p62nCMonjebPCZ5lhramaO4csrL4bmKdCw5i" +
        "XEEaQdwaA8k7Pvv2pkT+X50ZJKBQAaiHo2yRILI5n15UZ4y0fB+HCvA5qebZtkM0" +
        "gFqLPxNy1f8oYXuG9KE6sRn/pRwuYuBYD3eAqP6GquO0DkJKmq8RXeewx8ijUBd7" +
        "2xiZlbnBZxwvu5eEH5XD9iqf+liS+yA1wORQtQhSwuWApk9acaIP9IjyW2zojAtS" +
        "hwIDAQAB"
        )!
        let key = try _RSA.Signing.PublicKey(derRepresentation: derKey)
        XCTAssertEqual(derKey, key.derRepresentation)
    }

    func testParsingSPKIPublicKeyPEM() throws {
        let pemKey = """
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA509zjqylvktpuN3zMpdw
        YwsZ2dp9/cJZ2Krp2EqK+UvMJcp4T3O9rWPMZk1RocQWLpfSwF8jtfyy1OHDQEZh
        7UkpnlHmCwlNzzCj+/eaC+JP2Dy6p62nCMonjebPCZ5lhramaO4csrL4bmKdCw5i
        XEEaQdwaA8k7Pvv2pkT+X50ZJKBQAaiHo2yRILI5n15UZ4y0fB+HCvA5qebZtkM0
        gFqLPxNy1f8oYXuG9KE6sRn/pRwuYuBYD3eAqP6GquO0DkJKmq8RXeewx8ijUBd7
        2xiZlbnBZxwvu5eEH5XD9iqf+liS+yA1wORQtQhSwuWApk9acaIP9IjyW2zojAtS
        hwIDAQAB
        -----END PUBLIC KEY-----
        """
        let key = try _RSA.Signing.PublicKey(pemRepresentation: pemKey)
        XCTAssertEqual(pemKey, key.pemRepresentation)
    }

    private func testPKCS1Group(_ group: RSAPKCS1TestGroup) throws {
        let derKey = try _RSA.Signing.PublicKey(derRepresentation: group.keyDerBytes)
        let pemKey = try _RSA.Signing.PublicKey(pemRepresentation: group.keyPem)

        XCTAssertEqual(derKey.derRepresentation, pemKey.derRepresentation)
        XCTAssertEqual(derKey.pemRepresentation, pemKey.pemRepresentation)

        for test in group.tests {
            let valid: Bool

            let signature = _RSA.Signing.RSASignature(rawRepresentation: test.signatureBytes)

            switch group.sha {
            case "SHA-256":
                valid = derKey.isValidSignature(signature, for: SHA256.hash(data: test.messageBytes), padding: .insecurePKCS1v1_5)
            case "SHA-512":
                valid = derKey.isValidSignature(signature, for: SHA512.hash(data: test.messageBytes), padding: .insecurePKCS1v1_5)
            default:
                preconditionFailure("Unexpected sha: \(group.sha)")
            }

            XCTAssertEqual(valid, test.expectedValidity, "test number \(test.tcId) failed, expected \(test.result) but got \(valid)")
        }
    }

    private func testPSSGroup(_ group: RSAPSSTestGroup) throws {
        let derKey = try _RSA.Signing.PublicKey(derRepresentation: group.keyDerBytes)
        let pemKey = try _RSA.Signing.PublicKey(pemRepresentation: group.keyPem)

        XCTAssertEqual(derKey.derRepresentation, pemKey.derRepresentation)
        XCTAssertEqual(derKey.pemRepresentation, pemKey.pemRepresentation)

        guard group.sha == group.mgfSha else {
            // We only support PSS where the MGF digest and the message digest are the same, skip.
            return
        }

        switch (group.sha, group.sLen) {
        case ("SHA-1", 20),
            ("SHA-256", 32),
            ("SHA-384", 48),
            ("SHA-512", 52):
            // Supported hash functions using the same length salt as their digest size, supported.
            ()
        default:
            // Unsupported hash function or unsupported salt length, skip.
            return
        }

        for test in group.tests {
            let valid: Bool

            let signature = _RSA.Signing.RSASignature(rawRepresentation: test.signatureBytes)

            switch group.sha {
            case "SHA-1":
                valid = derKey.isValidSignature(signature, for: Insecure.SHA1.hash(data: test.messageBytes), padding: .PSS)
            case "SHA-224":
                // Unsupported but not in error, skip.
                continue
            case "SHA-256":
                valid = derKey.isValidSignature(signature, for: SHA256.hash(data: test.messageBytes), padding: .PSS)
            case "SHA-384":
                valid = derKey.isValidSignature(signature, for: SHA384.hash(data: test.messageBytes), padding: .PSS)
            case "SHA-512":
                valid = derKey.isValidSignature(signature, for: SHA512.hash(data: test.messageBytes), padding: .PSS)
            default:
                preconditionFailure("Unexpected sha: \(group.sha)")
            }

            XCTAssertEqual(valid, test.expectedValidity, "test number \(test.tcId) failed, expected \(test.result) but got \(valid)")
        }
    }

    private func pemForDERBytes(discriminator: String, derBytes: Data) -> String {
        let lineLength = 64
        var encoded = derBytes.base64EncodedString()[...]
        let pemLineCount = (encoded.utf8.count + lineLength) / lineLength
        var pemLines = [Substring]()
        pemLines.reserveCapacity(pemLineCount + 2)

        pemLines.append("-----BEGIN \(discriminator)-----")

        while encoded.count > 0 {
            let prefixIndex = encoded.index(encoded.startIndex, offsetBy: lineLength, limitedBy: encoded.endIndex) ?? encoded.endIndex
            pemLines.append(encoded[..<prefixIndex])
            encoded = encoded[prefixIndex...]
        }

        pemLines.append("-----END \(discriminator)-----")

        return pemLines.joined(separator: "\n")
    }
}


// Codable structures for our test vectors.
struct RSAPKCS1TestGroup: Codable {
    var keyDer: String
    var keyPem: String
    var sha: String
    var tests: [RSATest]

    var keyDerBytes: Data {
        return try! Data(hexString: self.keyDer)
    }
}

struct RSAPSSTestGroup: Codable {
    var keyDer: String
    var keyPem: String
    var sha: String
    var tests: [RSATest]
    var mgfSha: String
    var sLen: Int

    var keyDerBytes: Data {
        return try! Data(hexString: self.keyDer)
    }
}

struct RSATest: Codable {
    var tcId: Int
    var comment: String
    var msg: String
    var sig: String
    var result: String
    var flags: [String]

    var messageBytes: Data {
        return try! Data(hexString: self.msg)
    }

    var signatureBytes: Data {
        return try! Data(hexString: self.sig)
    }

    var expectedValidity: Bool {
        switch self.result {
        case "valid":
            return true
        case "invalid":
            return false
        case "acceptable":
            if self.flags.contains("MissingNull") {
                return false
            } else {
                return true
            }
        default:
            fatalError("Unexpected validity")
        }
    }
}
