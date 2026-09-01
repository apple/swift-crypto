//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftCrypto project authors
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
import CryptoBoringWrapper
@testable import CryptoExtras

final class TestRSASigning: XCTestCase {

    func test_rsaPssParameters() throws {
        let rsaPssPublicKeyPEM = """
        -----BEGIN PUBLIC KEY-----
        MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAaEaMBgGCSqGSIb3DQEB
        CDALBglghkgBZQMEAgGiAwIBIAOCAQ8AMIIBCgKCAQEAvcOaxSJoSiiXIQme6HEF
        d0/QHjtk5+U1RbeejxeUR80Q1f8E5v7+uIBEFVbwZpIJZtmSB3bxbS31rOBGVcrI
        IAfCnUlq6DK1fEL1fgn61XMiSSyKr75L5ZXv9Rib95h3lrNbhW0DUaXzf61kw3+Z
        4KV1btD7C+fdiLzPm18UQv8jJSbCE6hv3MWdkG3NcwgZC+iXwz3DFcsclyYg/+Om
        0hx8UJ/34vNpeE+0MHwyl0j/eO7izrzTZnfsm4ZRaU3mw0ORDQmo8MyIDFa55R/v
        30otk9y3LFkaeEyl1+7VFjJzoOEtze6VkTEzV8e/BTu4eXlKQ6CEYvHhUkNmHGC+
        mwIDAQAB
        -----END PUBLIC KEY-----
        """

        let rsaPssPublicKeyDER = Data(base64Encoded:
            "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAaEaMBgGCSqGSIb3DQEB" +
            "CDALBglghkgBZQMEAgGiAwIBIAOCAQ8AMIIBCgKCAQEAxPJvJDGPzb2rBWfE5JCB" +
            "p2OAmR46zIbaVjIR1lUabKCdb5CxdnHvQBymp3AlvOGTNzSLxTXOaYn7MzeFvAVI" +
            "mpRRzXzalG0ZfM4AkPBtjPz93pPLWEfgk+/i+JLWlWUStUGgGKNbJn4yJ8cJ8n+E" +
            "/5+ry+tUYHEJm9A4/HwH4Agg78kPtnEvIvdC/aIw4TEpjZDewVNAEW2rBuQNd01r" +
            "fAo2CSzbH76gL02mnLuvh1xyrKz+v9gyo9Taw273KU+83HPs91obgX4WpEfWOnd6" +
            "LMJHRZo92FXnW6IHkCdz12khyS1TVIq4ONwjvmS6q3V9UwQg/uuyoSNnRfWXvZXQ" +
            "aQIDAQAB"
        )!

        let rsaPssPublicKey1024PEM = """
        -----BEGIN PUBLIC KEY-----
        MIHPMD0GCSqGSIb3DQEBCjAwoA0wCwYJYIZIAWUDBAIBoRowGAYJKoZIhvcNAQEI
        MAsGCWCGSAFlAwQCAaIDAgEgA4GNADCBiQKBgQDGv67JltnwgkFxQOI8YUldC1LG
        rCLOpyAN/Vq4WyLQ6TKcPevcYA8XmuXL8tC85rMQQG1GMwMWKcf/kf0NDKblUFjZ
        BevUPmQF3Jadsn9ST+RMn8D+kq31Hdc0UG/WjZSpMHTkc8SWIjr2E6DIILn/OA/w
        G3jVOeTsEfUeGExhVwIDAQAB
        -----END PUBLIC KEY-----
        """

        let rsaPssPublicKey1024DER = Data(base64Encoded:
            "MIHPMD0GCSqGSIb3DQEBCjAwoA0wCwYJYIZIAWUDBAIBoRowGAYJKoZIhvcNAQEI" +
            "MAsGCWCGSAFlAwQCAaIDAgEgA4GNADCBiQKBgQC7LZLbFhzOCoTmXEABRsyOkRiB" +
            "18XkkJBwTkn2JES1jVZogXtcq5ZV+KmPulOrzLuaC45IliS5OZ1hJuC7m8/devXk" +
            "HaNId+y2cZxRYnfNCsEzvTryxt+01VMQJA4VHsdmhJO6TEIUzDIfj3BlahZuoU11" +
            "VZ4wgVIpYymQidJigQIDAQAB"
        )!

        XCTAssertEqual(try _RSA.Signing.PublicKey(pemRepresentation: rsaPssPublicKeyPEM).keySizeInBits, 2048)
        XCTAssertEqual(try _RSA.Signing.PublicKey(derRepresentation: rsaPssPublicKeyDER).keySizeInBits, 2048)
        XCTAssertEqual(try _RSA.Signing.PublicKey(unsafePEMRepresentation: rsaPssPublicKey1024PEM).keySizeInBits, 1024)
        XCTAssertEqual(try _RSA.Signing.PublicKey(unsafeDERRepresentation: rsaPssPublicKey1024DER).keySizeInBits, 1024)
    }

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

    func test_wycheproofPrimitives() throws {
        try wycheproofTest(
            jsonName: "rsa_oaep_2048_sha1_mgf1sha1_test",
            testFunction: self.testPrimeFactors)
        try wycheproofTest(
            jsonName: "rsa_oaep_2048_sha256_mgf1sha256_test",
            testFunction: self.testPrimeFactors)
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
            (_RSA.Signing.PrivateKey(unsafeKeySize: .init(bitCount: 1024)), 1024),
        ]

        for (key, size) in keysAndSizes {
            XCTAssertEqual(size, key.keySizeInBits)
            XCTAssertEqual(size, key.publicKey.keySizeInBits)
        }

        try XCTAssertThrowsError((_RSA.Signing.PrivateKey(keySize: .init(bitCount: 1024)), 1024))
    }

    // The default initializers require a modulus of at least 2048 bits.
    func testRejectKeysBelow2048BitMinimum() throws {
        // Equivalent key: `openssl genrsa -traditional 512`, converted to the encodings below.
        let _512BitRSAPrivateKeyPEM = """
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

        let _512BitRSAPublicKeyPEM = """
        -----BEGIN PUBLIC KEY-----
        MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOJMTCxw5nMxXCQgsOIRVCu8z1t58s5r
        2qSqwpZQvQZLlVrhYTpEnHFD6QbX8lHkk1Z3HZ1vjxW89ARPh94cG+0CAwEAAQ==
        -----END PUBLIC KEY-----
        """

        let _512BitRSAPrivateKeyPKCS8PEM = """
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

        let _512BitRSAPrivateKeyDER = Data(base64Encoded:
            "MIIBPAIBAAJBAOJMTCxw5nMxXCQgsOIRVCu8z1t58s5r2qSqwpZQvQZLlVr" +
            "hYTpEnHFD6QbX8lHkk1Z3HZ1vjxW89ARPh94cG+0CAwEAAQJBAMdmOVyTYs" +
            "wvuyPuVk3svQEJDqFpFATFTlP4TxuKKvTmbdQuVCorMmLLKThDI3pDNWKuA" +
            "vV+mqUDwk8lM0TvItUCIQD/p0sUPuATOc17qrebax6DQjAzfzzHr2iwZGX+" +
            "uq27swIhAOKa0YoCvcJYsODBvtIS//8cE9r2mWDwPxp3yAKxunnfAiATrhg" +
            "sfc6YDEoSLAkoUK2vowe83x2ZrZocgg4L9ujq2wIhAIIKCF9jzVO/I9oHNS" +
            "NG5gOXMEnCpCg+Fmhw/qWVKocPAiEAjR4Tgjp6d5ZsGUK9IHGsNWP1ySrag" +
            "7MWbrFpUouirbQ="
        )!

        let _512BitRSAPrivateKeyPKCS8DER = Data(base64Encoded:
            "MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEA4kxMLHDmczF" +
            "cJCCw4hFUK7zPW3nyzmvapKrCllC9BkuVWuFhOkSccUPpBtfyUeSTVncdnW" +
            "+PFbz0BE+H3hwb7QIDAQABAkEAx2Y5XJNizC+7I+5WTey9AQkOoWkUBMVOU" +
            "/hPG4oq9OZt1C5UKisyYsspOEMjekM1Yq4C9X6apQPCTyUzRO8i1QIhAP+n" +
            "SxQ+4BM5zXuqt5trHoNCMDN/PMevaLBkZf66rbuzAiEA4prRigK9wliw4MG" +
            "+0hL//xwT2vaZYPA/GnfIArG6ed8CIBOuGCx9zpgMShIsCShQra+jB7zfHZ" +
            "mtmhyCDgv26OrbAiEAggoIX2PNU78j2gc1I0bmA5cwScKkKD4WaHD+pZUqh" +
            "w8CIQCNHhOCOnp3lmwZQr0gcaw1Y/XJKtqDsxZusWlSi6KttA=="
        )!

        let _512BitRSAPublicKeyDER = Data(base64Encoded:
            "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOJMTCxw5nMxXCQgsOIRVCu8z1t" +
            "58s5r2qSqwpZQvQZLlVrhYTpEnHFD6QbX8lHkk1Z3HZ1vjxW89ARPh94cG+" +
            "0CAwEAAQ=="
        )!

        XCTAssertThrowsError(try _RSA.Signing.PrivateKey(pemRepresentation: _512BitRSAPrivateKeyPEM))
        XCTAssertThrowsError(try _RSA.Signing.PrivateKey(pemRepresentation: _512BitRSAPrivateKeyPKCS8PEM))
        XCTAssertThrowsError(try _RSA.Signing.PrivateKey(derRepresentation: _512BitRSAPrivateKeyDER))
        XCTAssertThrowsError(try _RSA.Signing.PrivateKey(derRepresentation: _512BitRSAPrivateKeyPKCS8DER))
        XCTAssertThrowsError(try _RSA.Signing.PublicKey(pemRepresentation: _512BitRSAPublicKeyPEM))
        XCTAssertThrowsError(try _RSA.Signing.PublicKey(derRepresentation: _512BitRSAPublicKeyDER))

        // Generated via `openssl genrsa -traditional 2047`, then converted to the encodings below.
        let _2047BitRSAPrivateKeyPEM = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEoAIBAAKCAQBXog86uwpuCobeXXokHAePMu15O2Cwfvwx7/EzZl6jY70ConNX
        mzR5U39kQQpFa0dxRQdgUA8YpU5/8aILp3Yv0S2BssiuqdL5IkzdBzLNRhSQabuM
        +vyCQjImHF/bA28+5DKJ9uzIhywA9JS2o/4TtE6mLqWbFAY+dM716llarKJgzLh/
        Vg0mH6H5vDoo4D6z+M2jQRiUbV+yIiiaY8/SMyLltsZeEl/hx/NyACPSUAClVlsj
        vRRZzQl8oDybMVvUAbrIwR+ZVQltdqVgx5zVf8G3BHi7lUdyqxIt0QWQRBTTd1tY
        sSOKmVhYB+DvPv2IJKGXqKo+XKQBLmm9UIuxAgMBAAECggEAN/6hZJGnNHEdhHCO
        XwxZ+DI+czxxp9U8KFx87q72wcg1Ob27nbraaLvlppW4jmriF4pYED6XptPZuP8Y
        4AF9D0jFnx4yBQkWeYJlQsYau/ePpEcrRAYL2t+ZU6jFxxgGuVTuxiE1Y1ybzXB6
        pclbzBNmPeGIh/LfmoDgzVmVBs6FhBrl8z+eWciISgskTaESkboiV+HAzDBJ23gP
        LD0fjk69Dw75MS7QHBYm5jDIpXFvh+nPJOfwIAuaEQ9ZaF3Uh8zjBOyhtOSO9cdV
        wXME4sIvA7IqlGoacxUtjyoWarPqk/V4UWl7/Q8gZlRagqjaJ+DqpqrD6UFCxwvw
        KCyJ0QKBgQDTV7joBHuuw/RuDe8VwxUuRJTIcdrn6g2Kn3CxV9YLJhxr1doEmw3Y
        DASY7zddkgJjssbkub5FhySAlqOIz5ok62erHMsyC90VXqWDC1uFHW6EQh/N/S/A
        vgEuyIJ/dtxXYLFyozm0Az98A37nGGTSt9tphKsTPiHS1jOB3f9DbwKBgGomcW7T
        Slq0+VSGniD+ciB71UMrW9FcF9qsnTPXQGZV4JqpLvE/tEq7uyr/Dp6l3mstVmtL
        tBjkPef32oz3JXo32IWS37VZlu+3I2v7VQThFLnc3F0KUcZmH1Uy1my8itjP6jIf
        wNwiUObilCubgiGEVxfMb0G7juMETZYyuRLfAoGAVwIFcRfvZ4rrBagc5yOyg6Le
        cgtVqSbVvl1Xwts7lslw6ABZyo2fTHPeLKxHafFjpHIEqkPCDtPNdlcOKpP1jP+R
        ZYPsL8VslpCpqWKyogH07uReParfzwUqbX1FJH7lxd9cDqseZXr01vSFeVS0pX/m
        B/IDkF+DA08GU4/2uGcCgYAV1CP9e1vN/WtMc4ZvGIQVpAF+F5uBGSQapuaI85nd
        sYlHpMTvfX8w4xwhQmQaQdfUSHV+CQpXGBCW9EQwOt6tHHDdPw/b9jlwwEN7gCrC
        nxqpAf8a7vVUDEojNhocMEWJQnBRsG/zlOb4I93+fbMr+1ABp9u1M8G1c3wVCAdB
        FwKBgF8sJlG58EKSfdvhVNDRq4hC/yjcI6987rg2fmeX9QUYiwReniaesEoBdeHz
        OYWR3DtC5SNiDKuj7QmnRvNcbFwBz5dGOdiXytRtLkpwDArY/hV/hqeSH1nHU0fp
        LUScnTZr95HkLFIle1JCFXw0viGHKEBkdFvcuXIFON9KNTA/
        -----END RSA PRIVATE KEY-----
        """

        let _2047BitRSAPublicKeyPEM = """
        -----BEGIN PUBLIC KEY-----
        MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBXog86uwpuCobeXXokHAeP
        Mu15O2Cwfvwx7/EzZl6jY70ConNXmzR5U39kQQpFa0dxRQdgUA8YpU5/8aILp3Yv
        0S2BssiuqdL5IkzdBzLNRhSQabuM+vyCQjImHF/bA28+5DKJ9uzIhywA9JS2o/4T
        tE6mLqWbFAY+dM716llarKJgzLh/Vg0mH6H5vDoo4D6z+M2jQRiUbV+yIiiaY8/S
        MyLltsZeEl/hx/NyACPSUAClVlsjvRRZzQl8oDybMVvUAbrIwR+ZVQltdqVgx5zV
        f8G3BHi7lUdyqxIt0QWQRBTTd1tYsSOKmVhYB+DvPv2IJKGXqKo+XKQBLmm9UIux
        AgMBAAE=
        -----END PUBLIC KEY-----
        """

        let _2047BitRSAPrivateKeyPKCS8PEM = """
        -----BEGIN PRIVATE KEY-----
        MIIEugIBADANBgkqhkiG9w0BAQEFAASCBKQwggSgAgEAAoIBAFeiDzq7Cm4Kht5d
        eiQcB48y7Xk7YLB+/DHv8TNmXqNjvQKic1ebNHlTf2RBCkVrR3FFB2BQDxilTn/x
        ogundi/RLYGyyK6p0vkiTN0HMs1GFJBpu4z6/IJCMiYcX9sDbz7kMon27MiHLAD0
        lLaj/hO0TqYupZsUBj50zvXqWVqsomDMuH9WDSYfofm8OijgPrP4zaNBGJRtX7Ii
        KJpjz9IzIuW2xl4SX+HH83IAI9JQAKVWWyO9FFnNCXygPJsxW9QBusjBH5lVCW12
        pWDHnNV/wbcEeLuVR3KrEi3RBZBEFNN3W1ixI4qZWFgH4O8+/YgkoZeoqj5cpAEu
        ab1Qi7ECAwEAAQKCAQA3/qFkkac0cR2EcI5fDFn4Mj5zPHGn1TwoXHzurvbByDU5
        vbudutpou+WmlbiOauIXilgQPpem09m4/xjgAX0PSMWfHjIFCRZ5gmVCxhq794+k
        RytEBgva35lTqMXHGAa5VO7GITVjXJvNcHqlyVvME2Y94YiH8t+agODNWZUGzoWE
        GuXzP55ZyIhKCyRNoRKRuiJX4cDMMEnbeA8sPR+OTr0PDvkxLtAcFibmMMilcW+H
        6c8k5/AgC5oRD1loXdSHzOME7KG05I71x1XBcwTiwi8DsiqUahpzFS2PKhZqs+qT
        9XhRaXv9DyBmVFqCqNon4OqmqsPpQULHC/AoLInRAoGBANNXuOgEe67D9G4N7xXD
        FS5ElMhx2ufqDYqfcLFX1gsmHGvV2gSbDdgMBJjvN12SAmOyxuS5vkWHJICWo4jP
        miTrZ6scyzIL3RVepYMLW4UdboRCH839L8C+AS7Ign923FdgsXKjObQDP3wDfucY
        ZNK322mEqxM+IdLWM4Hd/0NvAoGAaiZxbtNKWrT5VIaeIP5yIHvVQytb0VwX2qyd
        M9dAZlXgmqku8T+0Sru7Kv8OnqXeay1Wa0u0GOQ95/fajPclejfYhZLftVmW77cj
        a/tVBOEUudzcXQpRxmYfVTLWbLyK2M/qMh/A3CJQ5uKUK5uCIYRXF8xvQbuO4wRN
        ljK5Et8CgYBXAgVxF+9niusFqBznI7KDot5yC1WpJtW+XVfC2zuWyXDoAFnKjZ9M
        c94srEdp8WOkcgSqQ8IO0812Vw4qk/WM/5Flg+wvxWyWkKmpYrKiAfTu5F49qt/P
        BSptfUUkfuXF31wOqx5levTW9IV5VLSlf+YH8gOQX4MDTwZTj/a4ZwKBgBXUI/17
        W839a0xzhm8YhBWkAX4Xm4EZJBqm5ojzmd2xiUekxO99fzDjHCFCZBpB19RIdX4J
        ClcYEJb0RDA63q0ccN0/D9v2OXDAQ3uAKsKfGqkB/xru9VQMSiM2GhwwRYlCcFGw
        b/OU5vgj3f59syv7UAGn27UzwbVzfBUIB0EXAoGAXywmUbnwQpJ92+FU0NGriEL/
        KNwjr3zuuDZ+Z5f1BRiLBF6eJp6wSgF14fM5hZHcO0LlI2IMq6PtCadG81xsXAHP
        l0Y52JfK1G0uSnAMCtj+FX+Gp5IfWcdTR+ktRJydNmv3keQsUiV7UkIVfDS+IYco
        QGR0W9y5cgU430o1MD8=
        -----END PRIVATE KEY-----
        """

        let _2047BitRSAPrivateKeyDER = Data(base64Encoded:
            "MIIEoAIBAAKCAQBXog86uwpuCobeXXokHAePMu15O2Cwfvwx7/EzZl6jY70" +
            "ConNXmzR5U39kQQpFa0dxRQdgUA8YpU5/8aILp3Yv0S2BssiuqdL5IkzdBz" +
            "LNRhSQabuM+vyCQjImHF/bA28+5DKJ9uzIhywA9JS2o/4TtE6mLqWbFAY+d" +
            "M716llarKJgzLh/Vg0mH6H5vDoo4D6z+M2jQRiUbV+yIiiaY8/SMyLltsZe" +
            "El/hx/NyACPSUAClVlsjvRRZzQl8oDybMVvUAbrIwR+ZVQltdqVgx5zVf8G" +
            "3BHi7lUdyqxIt0QWQRBTTd1tYsSOKmVhYB+DvPv2IJKGXqKo+XKQBLmm9UI" +
            "uxAgMBAAECggEAN/6hZJGnNHEdhHCOXwxZ+DI+czxxp9U8KFx87q72wcg1O" +
            "b27nbraaLvlppW4jmriF4pYED6XptPZuP8Y4AF9D0jFnx4yBQkWeYJlQsYa" +
            "u/ePpEcrRAYL2t+ZU6jFxxgGuVTuxiE1Y1ybzXB6pclbzBNmPeGIh/LfmoD" +
            "gzVmVBs6FhBrl8z+eWciISgskTaESkboiV+HAzDBJ23gPLD0fjk69Dw75MS" +
            "7QHBYm5jDIpXFvh+nPJOfwIAuaEQ9ZaF3Uh8zjBOyhtOSO9cdVwXME4sIvA" +
            "7IqlGoacxUtjyoWarPqk/V4UWl7/Q8gZlRagqjaJ+DqpqrD6UFCxwvwKCyJ" +
            "0QKBgQDTV7joBHuuw/RuDe8VwxUuRJTIcdrn6g2Kn3CxV9YLJhxr1doEmw3" +
            "YDASY7zddkgJjssbkub5FhySAlqOIz5ok62erHMsyC90VXqWDC1uFHW6EQh" +
            "/N/S/AvgEuyIJ/dtxXYLFyozm0Az98A37nGGTSt9tphKsTPiHS1jOB3f9Db" +
            "wKBgGomcW7TSlq0+VSGniD+ciB71UMrW9FcF9qsnTPXQGZV4JqpLvE/tEq7" +
            "uyr/Dp6l3mstVmtLtBjkPef32oz3JXo32IWS37VZlu+3I2v7VQThFLnc3F0" +
            "KUcZmH1Uy1my8itjP6jIfwNwiUObilCubgiGEVxfMb0G7juMETZYyuRLfAo" +
            "GAVwIFcRfvZ4rrBagc5yOyg6LecgtVqSbVvl1Xwts7lslw6ABZyo2fTHPeL" +
            "KxHafFjpHIEqkPCDtPNdlcOKpP1jP+RZYPsL8VslpCpqWKyogH07uReParf" +
            "zwUqbX1FJH7lxd9cDqseZXr01vSFeVS0pX/mB/IDkF+DA08GU4/2uGcCgYA" +
            "V1CP9e1vN/WtMc4ZvGIQVpAF+F5uBGSQapuaI85ndsYlHpMTvfX8w4xwhQm" +
            "QaQdfUSHV+CQpXGBCW9EQwOt6tHHDdPw/b9jlwwEN7gCrCnxqpAf8a7vVUD" +
            "EojNhocMEWJQnBRsG/zlOb4I93+fbMr+1ABp9u1M8G1c3wVCAdBFwKBgF8s" +
            "JlG58EKSfdvhVNDRq4hC/yjcI6987rg2fmeX9QUYiwReniaesEoBdeHzOYW" +
            "R3DtC5SNiDKuj7QmnRvNcbFwBz5dGOdiXytRtLkpwDArY/hV/hqeSH1nHU0" +
            "fpLUScnTZr95HkLFIle1JCFXw0viGHKEBkdFvcuXIFON9KNTA/"
        )!

        let _2047BitRSAPrivateKeyPKCS8DER = Data(base64Encoded:
            "MIIEugIBADANBgkqhkiG9w0BAQEFAASCBKQwggSgAgEAAoIBAFeiDzq7Cm4" +
            "Kht5deiQcB48y7Xk7YLB+/DHv8TNmXqNjvQKic1ebNHlTf2RBCkVrR3FFB2" +
            "BQDxilTn/xogundi/RLYGyyK6p0vkiTN0HMs1GFJBpu4z6/IJCMiYcX9sDb" +
            "z7kMon27MiHLAD0lLaj/hO0TqYupZsUBj50zvXqWVqsomDMuH9WDSYfofm8" +
            "OijgPrP4zaNBGJRtX7IiKJpjz9IzIuW2xl4SX+HH83IAI9JQAKVWWyO9FFn" +
            "NCXygPJsxW9QBusjBH5lVCW12pWDHnNV/wbcEeLuVR3KrEi3RBZBEFNN3W1" +
            "ixI4qZWFgH4O8+/YgkoZeoqj5cpAEuab1Qi7ECAwEAAQKCAQA3/qFkkac0c" +
            "R2EcI5fDFn4Mj5zPHGn1TwoXHzurvbByDU5vbudutpou+WmlbiOauIXilgQ" +
            "Ppem09m4/xjgAX0PSMWfHjIFCRZ5gmVCxhq794+kRytEBgva35lTqMXHGAa" +
            "5VO7GITVjXJvNcHqlyVvME2Y94YiH8t+agODNWZUGzoWEGuXzP55ZyIhKCy" +
            "RNoRKRuiJX4cDMMEnbeA8sPR+OTr0PDvkxLtAcFibmMMilcW+H6c8k5/AgC" +
            "5oRD1loXdSHzOME7KG05I71x1XBcwTiwi8DsiqUahpzFS2PKhZqs+qT9XhR" +
            "aXv9DyBmVFqCqNon4OqmqsPpQULHC/AoLInRAoGBANNXuOgEe67D9G4N7xX" +
            "DFS5ElMhx2ufqDYqfcLFX1gsmHGvV2gSbDdgMBJjvN12SAmOyxuS5vkWHJI" +
            "CWo4jPmiTrZ6scyzIL3RVepYMLW4UdboRCH839L8C+AS7Ign923FdgsXKjO" +
            "bQDP3wDfucYZNK322mEqxM+IdLWM4Hd/0NvAoGAaiZxbtNKWrT5VIaeIP5y" +
            "IHvVQytb0VwX2qydM9dAZlXgmqku8T+0Sru7Kv8OnqXeay1Wa0u0GOQ95/f" +
            "ajPclejfYhZLftVmW77cja/tVBOEUudzcXQpRxmYfVTLWbLyK2M/qMh/A3C" +
            "JQ5uKUK5uCIYRXF8xvQbuO4wRNljK5Et8CgYBXAgVxF+9niusFqBznI7KDo" +
            "t5yC1WpJtW+XVfC2zuWyXDoAFnKjZ9Mc94srEdp8WOkcgSqQ8IO0812Vw4q" +
            "k/WM/5Flg+wvxWyWkKmpYrKiAfTu5F49qt/PBSptfUUkfuXF31wOqx5levT" +
            "W9IV5VLSlf+YH8gOQX4MDTwZTj/a4ZwKBgBXUI/17W839a0xzhm8YhBWkAX" +
            "4Xm4EZJBqm5ojzmd2xiUekxO99fzDjHCFCZBpB19RIdX4JClcYEJb0RDA63" +
            "q0ccN0/D9v2OXDAQ3uAKsKfGqkB/xru9VQMSiM2GhwwRYlCcFGwb/OU5vgj" +
            "3f59syv7UAGn27UzwbVzfBUIB0EXAoGAXywmUbnwQpJ92+FU0NGriEL/KNw" +
            "jr3zuuDZ+Z5f1BRiLBF6eJp6wSgF14fM5hZHcO0LlI2IMq6PtCadG81xsXA" +
            "HPl0Y52JfK1G0uSnAMCtj+FX+Gp5IfWcdTR+ktRJydNmv3keQsUiV7UkIVf" +
            "DS+IYcoQGR0W9y5cgU430o1MD8="
        )!

        let _2047BitRSAPublicKeyDER = Data(base64Encoded:
            "MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBXog86uwpuCobeXXo" +
            "kHAePMu15O2Cwfvwx7/EzZl6jY70ConNXmzR5U39kQQpFa0dxRQdgUA8YpU" +
            "5/8aILp3Yv0S2BssiuqdL5IkzdBzLNRhSQabuM+vyCQjImHF/bA28+5DKJ9" +
            "uzIhywA9JS2o/4TtE6mLqWbFAY+dM716llarKJgzLh/Vg0mH6H5vDoo4D6z" +
            "+M2jQRiUbV+yIiiaY8/SMyLltsZeEl/hx/NyACPSUAClVlsjvRRZzQl8oDy" +
            "bMVvUAbrIwR+ZVQltdqVgx5zVf8G3BHi7lUdyqxIt0QWQRBTTd1tYsSOKmV" +
            "hYB+DvPv2IJKGXqKo+XKQBLmm9UIuxAgMBAAE="
        )!

        XCTAssertThrowsError(try _RSA.Signing.PrivateKey(pemRepresentation: _2047BitRSAPrivateKeyPEM))
        XCTAssertThrowsError(try _RSA.Signing.PrivateKey(pemRepresentation: _2047BitRSAPrivateKeyPKCS8PEM))
        XCTAssertThrowsError(try _RSA.Signing.PrivateKey(derRepresentation: _2047BitRSAPrivateKeyDER))
        XCTAssertThrowsError(try _RSA.Signing.PrivateKey(derRepresentation: _2047BitRSAPrivateKeyPKCS8DER))
        XCTAssertThrowsError(try _RSA.Signing.PublicKey(pemRepresentation: _2047BitRSAPublicKeyPEM))
        XCTAssertThrowsError(try _RSA.Signing.PublicKey(derRepresentation: _2047BitRSAPublicKeyDER))
    }

    // The unsafe initializers require a modulus of at least 1024 bits. 1017 bits occupies 128 bytes,
    // the same as 1024.
    func testRejectKeysBelow1024BitMinimum() throws {
        // Generated via `openssl genrsa -traditional 1017`, then converted to the encodings below.
        let _1017BitRSAPrivateKeyPEM = """
        -----BEGIN RSA PRIVATE KEY-----
        MIICWAIBAAKBgAFVByFodT87fB0oWSEkwybEeqayqUavihFHLu3Ss/XuUxVosi5z
        lnzxbta17k8WXJYXa7OZC4jicxQer5xrZr9Op1k99zlJUbMtznl+BiSRKoAOjmsQ
        mLPU5er1hF1MnHUJsS1SgoTbR0CLPFNh4ai7WtOY6bWv/k9B03xNPeRVAgMBAAEC
        gYAAhvHcYWZL0DELpKSoPdDPLV5PSlE7fEjJD37dcsvtXBIaXaRsRybcZ/jxE2qq
        dvHKHphqp/vtfZYF9yKMZd9xcsxceGTRWR9kxQdKe6r9y1gzF1piRAyU4UcyjzFc
        h4w4psX3AqqN4qpQJgYUZamSRnnoJ3Vq7u/oR3W0P+PL3QJAGTnDt6UAHahmdryj
        KMFyQan+GU/eo6KDD84blk1L8axsEHtKUvtVBOWPRaR2WJI+q26adZbVvp707brW
        8sa+9wJADYTjZOw5A2C+mXlbBwV78cLrXwsZ/+5zrlGH5dMuDYbuJH3InXK/SguL
        f/OqQmrtUwSmL5QfQ//QPbUpsioIEwJABg1h8/HWsUbyLpLb4q9nJnIO0SvkkwYu
        w+ADpnAtRHLGCr5J+tbqcx5Q3biz3FRaTO9gh84EwpOI2HD3mZAtyQJABk3sRQor
        5DlfaO7A1ltmW23MmXvx2fn3FFmNCE4c8c30jCvkPBhgwET1/utAgMygc9B9Nz7Z
        /bn0AHLVSPJ05QJAFJqFaLd6j9v/WK7noJk0f7lWTZnfeRkZPxJh4AobfnGKV1yO
        +mB6mLJo/StOBrM82IdCBXTHRYYS2zUCCoJG1Q==
        -----END RSA PRIVATE KEY-----
        """

        let _1017BitRSAPublicKeyPEM = """
        -----BEGIN PUBLIC KEY-----
        MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgAFVByFodT87fB0oWSEkwybEeqay
        qUavihFHLu3Ss/XuUxVosi5zlnzxbta17k8WXJYXa7OZC4jicxQer5xrZr9Op1k9
        9zlJUbMtznl+BiSRKoAOjmsQmLPU5er1hF1MnHUJsS1SgoTbR0CLPFNh4ai7WtOY
        6bWv/k9B03xNPeRVAgMBAAE=
        -----END PUBLIC KEY-----
        """

        let _1017BitRSAPrivateKeyPKCS8PEM = """
        -----BEGIN PRIVATE KEY-----
        MIICcgIBADANBgkqhkiG9w0BAQEFAASCAlwwggJYAgEAAoGAAVUHIWh1Pzt8HShZ
        ISTDJsR6prKpRq+KEUcu7dKz9e5TFWiyLnOWfPFu1rXuTxZclhdrs5kLiOJzFB6v
        nGtmv06nWT33OUlRsy3OeX4GJJEqgA6OaxCYs9Tl6vWEXUycdQmxLVKChNtHQIs8
        U2HhqLta05jpta/+T0HTfE095FUCAwEAAQKBgACG8dxhZkvQMQukpKg90M8tXk9K
        UTt8SMkPft1yy+1cEhpdpGxHJtxn+PETaqp28coemGqn++19lgX3Ioxl33FyzFx4
        ZNFZH2TFB0p7qv3LWDMXWmJEDJThRzKPMVyHjDimxfcCqo3iqlAmBhRlqZJGeegn
        dWru7+hHdbQ/48vdAkAZOcO3pQAdqGZ2vKMowXJBqf4ZT96jooMPzhuWTUvxrGwQ
        e0pS+1UE5Y9FpHZYkj6rbpp1ltW+nvTtutbyxr73AkANhONk7DkDYL6ZeVsHBXvx
        wutfCxn/7nOuUYfl0y4Nhu4kfcidcr9KC4t/86pCau1TBKYvlB9D/9A9tSmyKggT
        AkAGDWHz8daxRvIuktvir2cmcg7RK+STBi7D4AOmcC1EcsYKvkn61upzHlDduLPc
        VFpM72CHzgTCk4jYcPeZkC3JAkAGTexFCivkOV9o7sDWW2ZbbcyZe/HZ+fcUWY0I
        ThzxzfSMK+Q8GGDARPX+60CAzKBz0H03Ptn9ufQActVI8nTlAkAUmoVot3qP2/9Y
        ruegmTR/uVZNmd95GRk/EmHgCht+cYpXXI76YHqYsmj9K04GszzYh0IFdMdFhhLb
        NQIKgkbV
        -----END PRIVATE KEY-----
        """

        let _1017BitRSAPrivateKeyDER = Data(base64Encoded:
            "MIICWAIBAAKBgAFVByFodT87fB0oWSEkwybEeqayqUavihFHLu3Ss/XuUxV" +
            "osi5zlnzxbta17k8WXJYXa7OZC4jicxQer5xrZr9Op1k99zlJUbMtznl+Bi" +
            "SRKoAOjmsQmLPU5er1hF1MnHUJsS1SgoTbR0CLPFNh4ai7WtOY6bWv/k9B0" +
            "3xNPeRVAgMBAAECgYAAhvHcYWZL0DELpKSoPdDPLV5PSlE7fEjJD37dcsvt" +
            "XBIaXaRsRybcZ/jxE2qqdvHKHphqp/vtfZYF9yKMZd9xcsxceGTRWR9kxQd" +
            "Ke6r9y1gzF1piRAyU4UcyjzFch4w4psX3AqqN4qpQJgYUZamSRnnoJ3Vq7u" +
            "/oR3W0P+PL3QJAGTnDt6UAHahmdryjKMFyQan+GU/eo6KDD84blk1L8axsE" +
            "HtKUvtVBOWPRaR2WJI+q26adZbVvp707brW8sa+9wJADYTjZOw5A2C+mXlb" +
            "BwV78cLrXwsZ/+5zrlGH5dMuDYbuJH3InXK/SguLf/OqQmrtUwSmL5QfQ//" +
            "QPbUpsioIEwJABg1h8/HWsUbyLpLb4q9nJnIO0SvkkwYuw+ADpnAtRHLGCr" +
            "5J+tbqcx5Q3biz3FRaTO9gh84EwpOI2HD3mZAtyQJABk3sRQor5DlfaO7A1" +
            "ltmW23MmXvx2fn3FFmNCE4c8c30jCvkPBhgwET1/utAgMygc9B9Nz7Z/bn0" +
            "AHLVSPJ05QJAFJqFaLd6j9v/WK7noJk0f7lWTZnfeRkZPxJh4AobfnGKV1y" +
            "O+mB6mLJo/StOBrM82IdCBXTHRYYS2zUCCoJG1Q=="
        )!

        let _1017BitRSAPrivateKeyPKCS8DER = Data(base64Encoded:
            "MIICcgIBADANBgkqhkiG9w0BAQEFAASCAlwwggJYAgEAAoGAAVUHIWh1Pzt" +
            "8HShZISTDJsR6prKpRq+KEUcu7dKz9e5TFWiyLnOWfPFu1rXuTxZclhdrs5" +
            "kLiOJzFB6vnGtmv06nWT33OUlRsy3OeX4GJJEqgA6OaxCYs9Tl6vWEXUycd" +
            "QmxLVKChNtHQIs8U2HhqLta05jpta/+T0HTfE095FUCAwEAAQKBgACG8dxh" +
            "ZkvQMQukpKg90M8tXk9KUTt8SMkPft1yy+1cEhpdpGxHJtxn+PETaqp28co" +
            "emGqn++19lgX3Ioxl33FyzFx4ZNFZH2TFB0p7qv3LWDMXWmJEDJThRzKPMV" +
            "yHjDimxfcCqo3iqlAmBhRlqZJGeegndWru7+hHdbQ/48vdAkAZOcO3pQAdq" +
            "GZ2vKMowXJBqf4ZT96jooMPzhuWTUvxrGwQe0pS+1UE5Y9FpHZYkj6rbpp1" +
            "ltW+nvTtutbyxr73AkANhONk7DkDYL6ZeVsHBXvxwutfCxn/7nOuUYfl0y4" +
            "Nhu4kfcidcr9KC4t/86pCau1TBKYvlB9D/9A9tSmyKggTAkAGDWHz8daxRv" +
            "Iuktvir2cmcg7RK+STBi7D4AOmcC1EcsYKvkn61upzHlDduLPcVFpM72CHz" +
            "gTCk4jYcPeZkC3JAkAGTexFCivkOV9o7sDWW2ZbbcyZe/HZ+fcUWY0IThzx" +
            "zfSMK+Q8GGDARPX+60CAzKBz0H03Ptn9ufQActVI8nTlAkAUmoVot3qP2/9" +
            "YruegmTR/uVZNmd95GRk/EmHgCht+cYpXXI76YHqYsmj9K04GszzYh0IFdM" +
            "dFhhLbNQIKgkbV"
        )!

        let _1017BitRSAPublicKeyDER = Data(base64Encoded:
            "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgAFVByFodT87fB0oWSEkwyb" +
            "EeqayqUavihFHLu3Ss/XuUxVosi5zlnzxbta17k8WXJYXa7OZC4jicxQer5" +
            "xrZr9Op1k99zlJUbMtznl+BiSRKoAOjmsQmLPU5er1hF1MnHUJsS1SgoTbR" +
            "0CLPFNh4ai7WtOY6bWv/k9B03xNPeRVAgMBAAE="
        )!

        XCTAssertThrowsError(
            try _RSA.Signing.PrivateKey(unsafePEMRepresentation: _1017BitRSAPrivateKeyPEM)
        )
        XCTAssertThrowsError(
            try _RSA.Signing.PrivateKey(unsafePEMRepresentation: _1017BitRSAPrivateKeyPKCS8PEM)
        )
        XCTAssertThrowsError(
            try _RSA.Signing.PrivateKey(unsafeDERRepresentation: _1017BitRSAPrivateKeyDER)
        )
        XCTAssertThrowsError(
            try _RSA.Signing.PrivateKey(unsafeDERRepresentation: _1017BitRSAPrivateKeyPKCS8DER)
        )
        XCTAssertThrowsError(
            try _RSA.Signing.PublicKey(unsafePEMRepresentation: _1017BitRSAPublicKeyPEM)
        )
        XCTAssertThrowsError(
            try _RSA.Signing.PublicKey(unsafeDERRepresentation: _1017BitRSAPublicKeyDER)
        )
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

        XCTAssertEqual(try _RSA.Signing.PrivateKey(pemRepresentation: awkwardRSAPrivateKeyPEM).keySizeInBits, 2050)
        XCTAssertEqual(try _RSA.Signing.PrivateKey(pemRepresentation: awkwardRSAPrivateKeyPKCS8PEM).keySizeInBits, 2050)
        XCTAssertEqual(try _RSA.Signing.PrivateKey(derRepresentation: awkwardRSAPrivateKeyDER).keySizeInBits, 2050)
        XCTAssertEqual(try _RSA.Signing.PrivateKey(derRepresentation: awkwardRSAPrivateKeyPKCS8DER).keySizeInBits, 2050)
        XCTAssertEqual(try _RSA.Signing.PublicKey(pemRepresentation: awkwardRSAPublicKeyPEM).keySizeInBits, 2050)
        XCTAssertEqual(try _RSA.Signing.PublicKey(derRepresentation: awkwardRSAPublicKeyDER).keySizeInBits, 2050)
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

    func testParsingPKCS8PrivateKeyPEM() throws {
        let pemKey = """
        -----BEGIN PRIVATE KEY-----
        MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCmKCB/22l/q8ny
        ernraohemEndZ3+RFWpeXZcGpBiWmoUqmrlJOYEzYNwvMP3y2VKPRStWHzuVN/mc
        /QTytLNec7HbgJqUpHZSh1XrviysJjBaWkVrOVAOmeXLnyImbCBsvhjxTHECjner
        tnNRjuoPdSRhYU5+9filh/iQxVMTAZFeGAKwS5fSXh6nB7s9sEztJ01rFQ6myp7c
        xteyhRgNAKRIYoxjgOSrzalH5PWJZ94fS3J8xPzUF9WILojXUKAagHoA8nTD1bfF
        Jz2tFojnjbfBE8S4FUxiiflybtjlH1sZz7EqEATcu1ny/pludcfoKmHHFuuCA0q7
        XOHWtptfAgMBAAECggEAZB/iFaneFPUsKFYUGuyDaJ1URXrMwFyrUFoNXA8eUgKj
        JF1AMgPY+2DuzfEz1ldnDLadurPvb6ffXt6JUMfbHpuRHbiNbez88BZljD15JfON
        R6UGF+rddy797oniRkz57Q1Qcneh0eyP6IV1UDxShyYL2jKM3qzSPM2G15ZQzS43
        3xCTFEFFTxFdmDWxC4iV7LHgdwub/9+FX2M05GeVzZ2t35PtabJ/FVqbj29ANcdg
        Q7UAIFgAWfwfQSA1qXbx0LyChwuEEyef2h3ENnveJm8E9t03h6RGJky9IQVMP3B6
        0SzUmSGlEX0rXpq/dRNrC+3bBDyQB4ZagVGk41IB4QKBgQDXq1keSNi3o2a/c9Io
        007+Fqo3PRj1035/yq+qqm6J158q9WIIJS+b71ZQ62UR7yxWtm7DiFE0mXvP+aF/
        e767O6cOf9qrdMX+G8SpDRtmQzXVOsIv1J26cJezpdDeud6V5odUX6EdcErQqzcv
        uhTSOVWQbrq4SAAcAoWCsvYruwKBgQDFOnuQ2sEK3GPbFHzX7I+BKIe8bq2JkcBN
        cHgs9NHNd93pddbeITm1lp/XPv/uJiZU2nneMHpP04mT89WRlFNA5UpmD99Ra5yN
        wIeKaDuDf7k6NJNL/ubLkbrdjVV4feKN9c57tjGeaYwEB/qpaf6v1WiElLNLfvFo
        ZBPTEDVKrQKBgQCRHwCZq0UA1Nf3rfTVedLmkNO61cbs64JsdTOdcI9u+4NkAbgU
        aQlPMU5wpuTcm4bHVnzT3+9cqIaynHQ6d0cRcANqc0fuJWZxJbhAVMyCFGmt8Jro
        WnZEFS1POh2BMasATR30/WBJkd0V6o/48oq+JsxXotrL088XCe9S0h9prwKBgQCt
        jacKctUIf6OHN2Ich9hH6ah4ElS3CADWpC+8L7snOWGXfNCVK1ujBWamfJOttvho
        FtDCypn3AMjB3wGCV6ljI+HyKelztmRPAKrFCq/EKXKPW5B6gVYKsLRlHWem3e+s
        yC7pAgxrv6ksKvFSfylVBVAxysBzoMNB/z7KriqXCQKBgD735odQUJdsPZ3Swnbv
        Iq/roNK1tzFxb52IHS2r2WM9TX4OlQE1VSPTTs0f84wTS+XZAnDRGubN5GYBkmWp
        K8TpFCFPBP/Yv1Kngovn4O1MskoxTQraRBDjfC6O7OfcSCSMuVgB0Oofcp9iQjLA
        HV3KOnbYqvzmFv7OWnAszkTh
        -----END PRIVATE KEY-----

        """

        let key = try _RSA.Signing.PrivateKey(pemRepresentation: pemKey)
        XCTAssertEqual(pemKey, key.pkcs8PEMRepresentation)
    }

    func testConstructKeyFromRSANumbers() throws {
        /// Check we can successfully construct keys from known valid values from a test vector.
        for testVector in RFC9474TestVector.allValues {
            _ = try _RSA.Signing.PrivateKey(
                n: Data(hexString: testVector.n),
                e: Data(hexString: testVector.e),
                d: Data(hexString: testVector.d),
                p: Data(hexString: testVector.p),
                q: Data(hexString: testVector.q)
            )
            _ = try _RSA.Signing.PublicKey(
                n: Data(hexString: testVector.n),
                e: Data(hexString: testVector.e)
            )
        }
        /// Also check that we can provide each argument as a different `ContiguousBytes` type.
        /// NOTE: these calls use `try?` because they are guaranteed to fail; we're just checking these calls compile.
        let bytesValues: [any ContiguousBytes] = [Data(), [UInt8]()]
        _ = try? _RSA.Signing.PrivateKey(
            n: bytesValues.randomElement()!,
            e: bytesValues.randomElement()!,
            d: bytesValues.randomElement()!,
            p: bytesValues.randomElement()!,
            q: bytesValues.randomElement()!
        )
        _ = try? _RSA.Signing.PublicKey(
            n: bytesValues.randomElement()!,
            e: bytesValues.randomElement()!
        )
        // Modulus of the 512-bit key above: `openssl rsa -in key.pem -noout -modulus`.
        let _512BitModulus =
            "e24c4c2c70e673315c2420b0e211542bbccf5b79f2ce6bdaa4aac29650bd064b"
            + "955ae1613a449c7143e906d7f251e49356771d9d6f8f15bcf4044f87de1c1bed"
        XCTAssertThrowsError(
            try _RSA.Signing.PublicKey(n: Data(hexString: _512BitModulus), e: Data(hexString: "010001"))
        )
    }

    func testConstructAndUseKeyFromRSANumbersWhileRecoveringPrimes() throws {
        let data = Array("hello, world!".utf8)

        for testVector in RFC9474TestVector.allValues {
            let key = try _RSA.Signing.PrivateKey._createFromNumbers(
                n: Data(hexString: testVector.n),
                e: Data(hexString: testVector.e),
                d: Data(hexString: testVector.d)
            )

            let signature = try key.signature(for: data)
            let roundTripped = _RSA.Signing.RSASignature(rawRepresentation: signature.rawRepresentation)
            XCTAssertEqual(signature.rawRepresentation, roundTripped.rawRepresentation)
            XCTAssertTrue(key.publicKey.isValidSignature(roundTripped, for: data))
        }
    }

    func testGetKeyPrimitives() throws {
        for testVector in RFC9474TestVector.allValues {
            let n = try Data(hexString: testVector.n)
            let e = try Data(hexString: testVector.e)

            let primitives = try _RSA.Signing.PublicKey(n: n, e: e).getKeyPrimitives()
            XCTAssertEqual(primitives.modulus, n)
            XCTAssertEqual(primitives.publicExponent, e)
        }
    }

    private func testPKCS1Group(_ group: RSAPKCS1TestGroup) throws {
        let derKey: _RSA.Signing.PublicKey
        let pemKey: _RSA.Signing.PublicKey

        if group.keysize < 2048 {
            derKey = try _RSA.Signing.PublicKey(unsafeDERRepresentation: group.keyDerBytes)
            pemKey = try _RSA.Signing.PublicKey(unsafePEMRepresentation: group.keyPem)
        } else {
            derKey = try _RSA.Signing.PublicKey(derRepresentation: group.keyDerBytes)
            pemKey = try _RSA.Signing.PublicKey(pemRepresentation: group.keyPem)
        }

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

    private func testPrimeFactors(_ group: RSAPrimitivesTestGroup) throws {
        let n = try ArbitraryPrecisionInteger(hexString: group.n)
        let e = try ArbitraryPrecisionInteger(hexString: group.e)
        let d = try ArbitraryPrecisionInteger(hexString: group.d)

        let (p, q) = try _RSA.extractPrimeFactors(n: n, e: e, d: d)
        XCTAssertEqual(p * q, n, "The product of p and q should equal n; got \(p) * \(q) != \(n)")
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

    func test_invalidDERPublicKeyThrowsWithoutDoubleFree() throws {
        // SEQUENCE { INTEGER 0, INTEGER 0 }
        let badBase64 = "MAYCAQACAQ=="
        let badDER = Array(Data(base64Encoded: badBase64)!)
        XCTAssertThrowsError(try BoringSSLRSAPublicKey(derRepresentation: badDER))
    }

    func test_invalidPEMPublicKeyThrowsWithoutDoubleFree() throws {
        // SEQUENCE { INTEGER 0, INTEGER 0 }
        let badPEM = """
            -----BEGIN PUBLIC KEY-----
            MAYCAQACAQ==
            -----END PUBLIC KEY-----
            """
        XCTAssertThrowsError(try BoringSSLRSAPublicKey(pemRepresentation: badPEM))
    }
}


// Codable structures for our test vectors.
struct RSAPKCS1TestGroup: Codable {
    var keyDer: String
    var keyPem: String
    var sha: String
    var tests: [RSATest]
    var keysize: Int

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

struct RSAPrimitivesTestGroup: Codable {
    let n: String
    let e: String
    let d: String
    let privateKeyJwk: PrivateKeyJWK?

    struct PrivateKeyJWK: Codable {
        let kty: String
        let n: String
        let e: String
        let d: String
        let p: String
        let q: String
        let dp: String
        let dq: String
        let qi: String
    }
}

struct RSAPrimitivesTestVectors: Codable {
    let testGroups: [RSAPrimitivesTestGroup]
}

