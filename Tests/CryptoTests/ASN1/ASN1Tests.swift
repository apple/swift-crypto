//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import XCTest

#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// Skip tests that require @testable imports of CryptoKit.
#else
#if !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@testable import CryptoKit
#else
@testable import Crypto
#endif

class ASN1Tests: XCTestCase {
    func testSimpleASN1P256SPKI() throws {
        // Given a static SPKI structure, verifies the parse.
        let encodedSPKI = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2adMrdG7aUfZH57aeKFFM01dPnkxC18ScRb4Z6poMBgJtYlVtd9ly63URv57ZW0Ncs1LiZB7WATb3svu+1c7HQ=="
        let decodedSPKI = Array(Data(base64Encoded: encodedSPKI)!)

        let encodedExpectedKeyBytes = "BNmnTK3Ru2lH2R+e2nihRTNNXT55MQtfEnEW+GeqaDAYCbWJVbXfZcut1Eb+e2VtDXLNS4mQe1gE297L7vtXOx0="
        let expectedKeyBytes = Array(Data(base64Encoded: encodedExpectedKeyBytes)!)

        let result = try ASN1.parse(decodedSPKI)
        let spki = try ASN1.SubjectPublicKeyInfo(asn1Encoded: result)

        XCTAssertEqual(spki.algorithmIdentifier, .ecdsaP256)
        spki.key.withUnsafeBytes { XCTAssertEqual(Array($0), expectedKeyBytes) }

        // For SPKI we should be able to round-trip the serialization.
        var serializer = ASN1.Serializer()
        XCTAssertNoThrow(try serializer.serialize(spki))
        XCTAssertEqual(serializer.serializedBytes, decodedSPKI)
    }

    func testSimpleASN1P384SPKI() throws {
        let encodedSPKI = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEcBr0TNmgagf1ysckEA/3XLGx2amgzeHjDBZREqhCIVBrLhIiIR4zrJ8dqad/Y+zI2Hu8TIUbrzS/diFpFoE0YYKBTfYMCAUtaWuMb1oaBdFzWsLfYSSzF+ON1yeJCtro"
        let decodedSPKI = Array(Data(base64Encoded: encodedSPKI)!)

        let encodedExpectedKeyBytes = "BHAa9EzZoGoH9crHJBAP91yxsdmpoM3h4wwWURKoQiFQay4SIiEeM6yfHamnf2PsyNh7vEyFG680v3YhaRaBNGGCgU32DAgFLWlrjG9aGgXRc1rC32EksxfjjdcniQra6A=="
        let expectedKeyBytes = Array(Data(base64Encoded: encodedExpectedKeyBytes)!)

        let result = try ASN1.parse(decodedSPKI)
        let spki = try ASN1.SubjectPublicKeyInfo(asn1Encoded: result)

        XCTAssertEqual(spki.algorithmIdentifier, .ecdsaP384)
        spki.key.withUnsafeBytes { XCTAssertEqual(Array($0), expectedKeyBytes) }

        // For SPKI we should be able to round-trip the serialization.
        var serializer = ASN1.Serializer()
        XCTAssertNoThrow(try serializer.serialize(spki))
        XCTAssertEqual(serializer.serializedBytes, decodedSPKI)
    }

    func testSimpleASN1P521SPKI() throws {
        let encodedSPKI = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBTxMJZTRr9NcKmD7iTeX7ofcgz77JPTIDXOHFfS1tZHd9P0uAeK/ARwwDdsQpIKCvmtaO4O52oHqmczdrRwGtrHIBUTqaOw2Fqdiqt0fRQju9wH1Xi4h8u0h80MymUM0sbAQ70jHCeV0S0mGcJS8t3nfP+qLes30h297dPfV3SLsLg8M="
        let decodedSPKI = Array(Data(base64Encoded: encodedSPKI)!)

        let encodedExpectedKeyBytes = "BAFPEwllNGv01wqYPuJN5fuh9yDPvsk9MgNc4cV9LW1kd30/S4B4r8BHDAN2xCkgoK+a1o7g7nageqZzN2tHAa2scgFROpo7DYWp2Kq3R9FCO73AfVeLiHy7SHzQzKZQzSxsBDvSMcJ5XRLSYZwlLy3ed8/6ot6zfSHb3t099XdIuwuDww=="
        let expectedKeyBytes = Array(Data(base64Encoded: encodedExpectedKeyBytes)!)

        let result = try ASN1.parse(decodedSPKI)
        let spki = try ASN1.SubjectPublicKeyInfo(asn1Encoded: result)

        XCTAssertEqual(spki.algorithmIdentifier, .ecdsaP521)
        spki.key.withUnsafeBytes { XCTAssertEqual(Array($0), expectedKeyBytes) }

        // For SPKI we should be able to round-trip the serialization.
        var serializer = ASN1.Serializer()
        XCTAssertNoThrow(try serializer.serialize(spki))
        XCTAssertEqual(serializer.serializedBytes, decodedSPKI)
    }

    func testASN1SEC1PrivateKeyP256() throws {
        let encodedPrivateKey = "MHcCAQEEIFAV2+taX2/ht9HEcLQPtfyuRktTkn4S3RaCQwDmDnrloAoGCCqGSM49AwEHoUQDQgAE3Oed98X0hHmzHmmmgtf5rAVEv0jIeH61K61P5UyiCozn+fz+mlmBywvluiVvERiT9WZCd3tkPPWwbIr+a0dnwA=="
        let decodedPrivateKey = Array(Data(base64Encoded: encodedPrivateKey)!)

        let encodedPrivateKeyBytes = "UBXb61pfb+G30cRwtA+1/K5GS1OSfhLdFoJDAOYOeuU="
        let privateKeyBytes = Array(Data(base64Encoded: encodedPrivateKeyBytes)!)

        let encodedPublicKeyBytes = "BNznnffF9IR5sx5ppoLX+awFRL9IyHh+tSutT+VMogqM5/n8/ppZgcsL5bolbxEYk/VmQnd7ZDz1sGyK/mtHZ8A="
        let publicKeyBytes = Array(Data(base64Encoded: encodedPublicKeyBytes)!)

        let result = try ASN1.parse(decodedPrivateKey)
        let pkey = try ASN1.SEC1PrivateKey(asn1Encoded: result)

        XCTAssertEqual(pkey.algorithm, .ecdsaP256)
        pkey.privateKey.withUnsafeBytes { XCTAssertEqual(Array($0), privateKeyBytes) }
        pkey.publicKey!.withUnsafeBytes { XCTAssertEqual(Array($0), publicKeyBytes) }

        // For SEC1 we should be able to round-trip the serialization.
        var serializer = ASN1.Serializer()
        XCTAssertNoThrow(try serializer.serialize(pkey))
        XCTAssertEqual(serializer.serializedBytes, decodedPrivateKey)
    }

    func testASN1SEC1PrivateKeyP384() throws {
        let encodedPrivateKey = "MIGkAgEBBDAWv9iH6ZivZKtk5ihjvjlZCYc9JHyykqvmJ7JVQ50ZZWTkCPtIe7RSKzm+l7NJltqgBwYFK4EEACKhZANiAAQz0BBmMxeOj5XwTL1G4fqTYO2UAiYrUMixiRFlFKVY5I6jAgiEWdNbmte8o6dByo0No5YoyDHdG637xvuzGaWd+IT5LoBAVVv3AgL3ao3dA4aVhm6Yz6G6/2o3X7AH99c="
        let decodedPrivateKey = Array(Data(base64Encoded: encodedPrivateKey)!)

        let encodedPrivateKeyBytes = "Fr/Yh+mYr2SrZOYoY745WQmHPSR8spKr5ieyVUOdGWVk5Aj7SHu0Uis5vpezSZba"
        let privateKeyBytes = Array(Data(base64Encoded: encodedPrivateKeyBytes)!)

        let encodedPublicKeyBytes = "BDPQEGYzF46PlfBMvUbh+pNg7ZQCJitQyLGJEWUUpVjkjqMCCIRZ01ua17yjp0HKjQ2jlijIMd0brfvG+7MZpZ34hPkugEBVW/cCAvdqjd0DhpWGbpjPobr/ajdfsAf31w=="
        let publicKeyBytes = Array(Data(base64Encoded: encodedPublicKeyBytes)!)

        let result = try ASN1.parse(decodedPrivateKey)
        let pkey = try ASN1.SEC1PrivateKey(asn1Encoded: result)

        XCTAssertEqual(pkey.algorithm, .ecdsaP384)
        pkey.privateKey.withUnsafeBytes { XCTAssertEqual(Array($0), privateKeyBytes) }
        pkey.publicKey!.withUnsafeBytes { XCTAssertEqual(Array($0), publicKeyBytes) }

        // For SEC1 we should be able to round-trip the serialization.
        var serializer = ASN1.Serializer()
        XCTAssertNoThrow(try serializer.serialize(pkey))
        XCTAssertEqual(serializer.serializedBytes, decodedPrivateKey)
    }

    func testASN1SEC1PrivateKeyP521() throws {
        let encodedPrivateKey = "MIHcAgEBBEIBONszidL11f7D8LEbVGKG4A7768X16w35/m6OSPO7MGQcYhWHpgSV4NZ6AFKcksavZSCa59lYdAN+MA3sUjO7R/mgBwYFK4EEACOhgYkDgYYABAAzsbWlHXjMkaSQTBnBKcyPDy/x0nk+VlkYQJXkh+lPJSVEYLbrUZ1LdbfM9mGE7HpgyyELNRHy/BD1JdNnAVPemAC5VQjeGKbezrxz7D5iZNiZiQFVYtMBU3XSsuJrPWVSjBF7xIkOr06k2xg1qlOoXQ66EPHQlwEYJ3xATNKk8K2jlQ=="
        let decodedPrivateKey = Array(Data(base64Encoded: encodedPrivateKey)!)

        let encodedPrivateKeyBytes = "ATjbM4nS9dX+w/CxG1RihuAO++vF9esN+f5ujkjzuzBkHGIVh6YEleDWegBSnJLGr2UgmufZWHQDfjAN7FIzu0f5"
        let privateKeyBytes = Array(Data(base64Encoded: encodedPrivateKeyBytes)!)

        let encodedPublicKeyBytes = "BAAzsbWlHXjMkaSQTBnBKcyPDy/x0nk+VlkYQJXkh+lPJSVEYLbrUZ1LdbfM9mGE7HpgyyELNRHy/BD1JdNnAVPemAC5VQjeGKbezrxz7D5iZNiZiQFVYtMBU3XSsuJrPWVSjBF7xIkOr06k2xg1qlOoXQ66EPHQlwEYJ3xATNKk8K2jlQ=="
        let publicKeyBytes = Array(Data(base64Encoded: encodedPublicKeyBytes)!)

        let result = try ASN1.parse(decodedPrivateKey)
        let pkey = try ASN1.SEC1PrivateKey(asn1Encoded: result)

        XCTAssertEqual(pkey.algorithm, .ecdsaP521)
        pkey.privateKey.withUnsafeBytes { XCTAssertEqual(Array($0), privateKeyBytes) }
        pkey.publicKey!.withUnsafeBytes { XCTAssertEqual(Array($0), publicKeyBytes) }

        // For SEC1 we should be able to round-trip the serialization.
        var serializer = ASN1.Serializer()
        XCTAssertNoThrow(try serializer.serialize(pkey))
        XCTAssertEqual(serializer.serializedBytes, decodedPrivateKey)
    }

    func testASN1PKCS8PrivateKeyP256() throws {
        let encodedPrivateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCRQo0CoBKfTOhdgQHcQIVv21vIUsxmE3t9L1LqV00bahRANCAATDXEj3jviAtzgx4bnMa/081v+FXbp7O5D1KtKVdje+ckejGVLYuYKE4Lpf5jonefi6wtoCc/sWHlbLiNV5PEB9"
        let decodedPrivateKey = Array(Data(base64Encoded: encodedPrivateKey)!)

        let encodedPrivateKeyBytes = "CRQo0CoBKfTOhdgQHcQIVv21vIUsxmE3t9L1LqV00bY="
        let privateKeyBytes = Array(Data(base64Encoded: encodedPrivateKeyBytes)!)

        let encodedPublicKeyBytes = "BMNcSPeO+IC3ODHhucxr/TzW/4Vduns7kPUq0pV2N75yR6MZUti5goTgul/mOid5+LrC2gJz+xYeVsuI1Xk8QH0="
        let publicKeyBytes = Array(Data(base64Encoded: encodedPublicKeyBytes)!)

        let result = try ASN1.parse(decodedPrivateKey)
        let pkey = try ASN1.PKCS8PrivateKey(asn1Encoded: result)

        XCTAssertEqual(pkey.algorithm, .ecdsaP256)
        XCTAssertNil(pkey.privateKey.algorithm)  // OpenSSL nils this out for some reason
        pkey.privateKey.privateKey.withUnsafeBytes { XCTAssertEqual(Array($0), privateKeyBytes) }
        pkey.privateKey.publicKey!.withUnsafeBytes { XCTAssertEqual(Array($0), publicKeyBytes) }

        // For PKCS8 we should be able to round-trip the serialization.
        var serializer = ASN1.Serializer()
        XCTAssertNoThrow(try serializer.serialize(pkey))
        XCTAssertEqual(serializer.serializedBytes, decodedPrivateKey)
    }

    func testASN1PKCS8PrivateKeyP384() throws {
        let encodedPrivateKey = "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCKfeRAkTtGQG7bGao6Ca5MDDcmxttyr6HNmNoaSkmuYvBtLGLLBWm1+VHT602xOIihZANiAAS56RzXiLO5YvFI0qh/+T9DhOXfkm3K/jJSUAqV/hP0FUlIUR824cFVdMMQA1S100mETsxdT0QDqUGAinMTUBSyk9y+jR33Fw/A068ZQRlqTCa0ThS0vwxKhM/M4vhYeDE="
        let decodedPrivateKey = Array(Data(base64Encoded: encodedPrivateKey)!)

        let encodedPrivateKeyBytes = "in3kQJE7RkBu2xmqOgmuTAw3Jsbbcq+hzZjaGkpJrmLwbSxiywVptflR0+tNsTiI"
        let privateKeyBytes = Array(Data(base64Encoded: encodedPrivateKeyBytes)!)

        let encodedPublicKeyBytes = "BLnpHNeIs7li8UjSqH/5P0OE5d+Sbcr+MlJQCpX+E/QVSUhRHzbhwVV0wxADVLXTSYROzF1PRAOpQYCKcxNQFLKT3L6NHfcXD8DTrxlBGWpMJrROFLS/DEqEz8zi+Fh4MQ=="
        let publicKeyBytes = Array(Data(base64Encoded: encodedPublicKeyBytes)!)

        let result = try ASN1.parse(decodedPrivateKey)
        let pkey = try ASN1.PKCS8PrivateKey(asn1Encoded: result)

        XCTAssertEqual(pkey.algorithm, .ecdsaP384)
        XCTAssertNil(pkey.privateKey.algorithm)  // OpenSSL nils this out for some reason
        pkey.privateKey.privateKey.withUnsafeBytes { XCTAssertEqual(Array($0), privateKeyBytes) }
        pkey.privateKey.publicKey!.withUnsafeBytes { XCTAssertEqual(Array($0), publicKeyBytes) }

        // For PKCS8 we should be able to round-trip the serialization.
        var serializer = ASN1.Serializer()
        XCTAssertNoThrow(try serializer.serialize(pkey))
        XCTAssertEqual(serializer.serializedBytes, decodedPrivateKey)
    }

    func testASN1PKCS8PrivateKeyP521() throws {
        let encodedPrivateKey = "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB/rwbfr3a+rdHQvKToS6Fw1WxsVFy3Wq2ylWC+EyQv//nGiT5TQYIAV2WDmmud3WnczITapXAAe6eS66jHa+OxyGhgYkDgYYABADrY6IBU4t8BjSIvDWA4VrLILdUOFemM2G8phpJWlGpEO8Qmk28w5pdLD2j3chBvg0xBBi2k9Ked9L43R4E3+gPCAA3CY8v01xlA6npJvdAK0/Md4mY+p65Ehua95jXnSwrpF66+Q/se2ODvZPhXGKBvttxrKyBr9htmkAUv9Sdah+dWQ=="
        let decodedPrivateKey = Array(Data(base64Encoded: encodedPrivateKey)!)

        let encodedPrivateKeyBytes = "Af68G3692vq3R0Lyk6EuhcNVsbFRct1qtspVgvhMkL//5xok+U0GCAFdlg5prnd1p3MyE2qVwAHunkuuox2vjsch"
        let privateKeyBytes = Array(Data(base64Encoded: encodedPrivateKeyBytes)!)

        let encodedPublicKeyBytes = "BADrY6IBU4t8BjSIvDWA4VrLILdUOFemM2G8phpJWlGpEO8Qmk28w5pdLD2j3chBvg0xBBi2k9Ked9L43R4E3+gPCAA3CY8v01xlA6npJvdAK0/Md4mY+p65Ehua95jXnSwrpF66+Q/se2ODvZPhXGKBvttxrKyBr9htmkAUv9Sdah+dWQ=="
        let publicKeyBytes = Array(Data(base64Encoded: encodedPublicKeyBytes)!)

        let result = try ASN1.parse(decodedPrivateKey)
        let pkey = try ASN1.PKCS8PrivateKey(asn1Encoded: result)

        XCTAssertEqual(pkey.algorithm, .ecdsaP521)
        XCTAssertNil(pkey.privateKey.algorithm)  // OpenSSL nils this out for some reason
        pkey.privateKey.privateKey.withUnsafeBytes { XCTAssertEqual(Array($0), privateKeyBytes) }
        pkey.privateKey.publicKey!.withUnsafeBytes { XCTAssertEqual(Array($0), publicKeyBytes) }

        // For PKCS8 we should be able to round-trip the serialization.
        var serializer = ASN1.Serializer()
        XCTAssertNoThrow(try serializer.serialize(pkey))
        XCTAssertEqual(serializer.serializedBytes, decodedPrivateKey)
    }

    func testRejectDripFedASN1SPKIP256() throws {
        // This test drip-feeds an ASN.1 P256 SPKI block. It should never parse correctly until we feed the entire block.
        let encodedSPKI = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2adMrdG7aUfZH57aeKFFM01dPnkxC18ScRb4Z6poMBgJtYlVtd9ly63URv57ZW0Ncs1LiZB7WATb3svu+1c7HQ=="
        let decodedSPKI = Array(Data(base64Encoded: encodedSPKI)!)

        for index in decodedSPKI.indices {
            let expectSuccessfulParse = index == decodedSPKI.endIndex

            do {
                _ = try ASN1.parse(decodedSPKI[..<index])
                if !expectSuccessfulParse {
                    XCTFail("Unexpected successful parse with: \(decodedSPKI[...])")
                }
            } catch let error as CryptoKitASN1Error {
                if expectSuccessfulParse {
                    XCTFail("Unexpected failure (error: \(error)) with \(decodedSPKI[...])")
                }
            }
        }
    }

    func testASN1TypesRequireAppropriateTypeIdentifierToDecode() throws {
        // This is an ASN.1 REAL, a type we don't support
        let base64Node = "CQUDMUUtMQ=="
        let decodedReal = Array(Data(base64Encoded: base64Node)!)
        let parsed = try ASN1.parse(decodedReal)

        XCTAssertThrowsError(try ASN1.ASN1ObjectIdentifier(asn1Encoded: parsed),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try ASN1.sequence(parsed, identifier: .sequence, { _ in }),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try ASN1.ASN1OctetString(asn1Encoded: parsed),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try ASN1.ASN1BitString(asn1Encoded: parsed),
                             error: CryptoKitASN1Error.unexpectedFieldType)
        XCTAssertThrowsError(try Int(asn1Encoded: parsed),
                             error: CryptoKitASN1Error.unexpectedFieldType)
    }

    func testMultipleRootNodesAreForbidden() throws {
        // This is an ASN.1 REAL, a type we don't support, repeated
        let base64Node = "CQUDMUUtMQkFAzFFLTE="
        let decodedReal = Array(Data(base64Encoded: base64Node)!)
        XCTAssertThrowsError(try ASN1.parse(decodedReal),
                             error: CryptoKitASN1Error.invalidASN1Object)
    }

    func testTrailingBytesAreForbidden() throws {
        // This is an ASN.1 INTEGER with trailing junk bytes
        let base64Node = "AgEBAA=="
        let decodedInteger = Array(Data(base64Encoded: base64Node)!)
        XCTAssertThrowsError(try ASN1.parse(decodedInteger),
                             error: CryptoKitASN1Error.invalidASN1Object)
    }

    func testEmptyStringsDontDecode() throws {
        XCTAssertThrowsError(try ASN1.parse([]),
                             error: CryptoKitASN1Error.truncatedASN1Field)
    }

    func testRejectMultibyteTag() throws {
        // This is an ASN.1 INTEGER with a multibyte explicit tag, with the raw numerical value being 55.
        let base64Node = "vzcDAgEB"
        let decodedInteger = Array(Data(base64Encoded: base64Node)!)
        XCTAssertThrowsError(try ASN1.parse(decodedInteger),
                             error: CryptoKitASN1Error.invalidFieldIdentifier)
    }

    func testSequenceMustConsumeAllNodes() throws {
        // This is an ASN.1 SEQUENCE with two child nodes, both octet strings. We're going to consume only one.
        let base64Sequence = "MAwEBEFCQ0QEBEVGR0g="
        let decodedSequence = Array(Data(base64Encoded: base64Sequence)!)
        let parsed = try ASN1.parse(decodedSequence)

        do {
            try ASN1.sequence(parsed, identifier: .sequence) { nodes in
                // This is fine.
                XCTAssertNoThrow(try ASN1.ASN1OctetString(asn1Encoded: &nodes))
            }
        } catch let error as CryptoKitASN1Error {
            XCTAssertEqual(error, .invalidASN1Object)
        }
    }

    func testNodesErrorIfThereIsInsufficientData() throws {
        struct Stub: ASN1Parseable {
            init(asn1Encoded node: ASN1.ASN1Node) throws {
                XCTFail("Must not be called")
            }
        }

        // This is an ASN.1 SEQUENCE with two child nodes, both octet strings. We're going to consume both and then try
        // to eat the (nonexistent) next node.
        let base64Sequence = "MAwEBEFCQ0QEBEVGR0g="
        let decodedSequence = Array(Data(base64Encoded: base64Sequence)!)
        let parsed = try ASN1.parse(decodedSequence)

        do {
            try ASN1.sequence(parsed, identifier: .sequence) { nodes in
                XCTAssertNoThrow(try ASN1.ASN1OctetString(asn1Encoded: &nodes))
                XCTAssertNoThrow(try ASN1.ASN1OctetString(asn1Encoded: &nodes))
                _ = try Stub(asn1Encoded: &nodes)
            }
        } catch let error as CryptoKitASN1Error {
            XCTAssertEqual(error, .invalidASN1Object)
        }
    }

    func testRejectsIndefiniteLengthForm() throws {
        // This the first octets of a constructed object of unknown tag type (private, number 7) whose length
        // is indefinite. We reject this immediately, not even noticing that the rest of the data isn't here.
        XCTAssertThrowsError(try ASN1.parse([0xe7, 0x80]), error: CryptoKitASN1Error.unsupportedFieldLength)
    }

    func testRejectsUnterminatedASN1OIDSubidentifiers() throws {
        // This data contains the ASN.1 OID 2.6.7, with the last subidentifier having been mangled to set the top bit.
        // This makes it look like we're expecting more data in the OID, and we should flag it as truncated.
        let badBase64 = "BgJWhw=="
        let badNode = Array(Data(base64Encoded: badBase64)!)
        let parsed = try ASN1.parse(badNode)

        XCTAssertThrowsError(try ASN1.ASN1ObjectIdentifier(asn1Encoded: parsed),
                             error: CryptoKitASN1Error.invalidASN1Object)
    }

    func testRejectsMassiveIntegers() throws {
        // This is an ASN.1 integer containing UInt64.max * 2. This is too big for us to store, and we reject it.
        // This test may need to be rewritten if we either support arbitrary integers or move to platforms where
        // UInt is larger than 64 bits (seems unlikely).
        let badBase64 = "AgkB//////////4="
        let badNode = Array(Data(base64Encoded: badBase64)!)
        let parsed = try ASN1.parse(badNode)

        XCTAssertThrowsError(try Int(asn1Encoded: parsed),
                             error: CryptoKitASN1Error.invalidASN1Object)
    }

    func testStraightforwardPEMParsing() throws {
        let simplePEM = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBHli4jaj+JwWQlU0yhZUu+TdMPVhZ3wR2PS416Sz/K/oAoGCCqGSM49
AwEHoUQDQgAEOhvJhbc3zM4SJooCaWdyheY2E6wWkISg7TtxJYgb/S0Zz7WruJzG
O9zxi7HTvuXyQr7QKSBtdCGmHym+WoPsbA==
-----END EC PRIVATE KEY-----
"""
        let document = try ASN1.PEMDocument(pemString: simplePEM)
        XCTAssertEqual(document.type, "EC PRIVATE KEY")
        XCTAssertEqual(document.derBytes.count, 121)

        let parsed = try ASN1.parse(Array(document.derBytes))
        let pkey = try ASN1.SEC1PrivateKey(asn1Encoded: parsed)

        let reserialized = document.pemString
        XCTAssertEqual(reserialized, simplePEM)

        var serializer = ASN1.Serializer()
        XCTAssertNoThrow(try serializer.serialize(pkey))
        let reserialized2 = ASN1.PEMDocument(type: "EC PRIVATE KEY", derBytes: Data(serializer.serializedBytes))
        XCTAssertEqual(reserialized2.pemString, simplePEM)
    }

    func testTruncatedPEMDocumentsAreRejected() throws {
        // We drip feed the PEM one extra character at a time. It never parses successfully.
        let simplePEM = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBHli4jaj+JwWQlU0yhZUu+TdMPVhZ3wR2PS416Sz/K/oAoGCCqGSM49
AwEHoUQDQgAEOhvJhbc3zM4SJooCaWdyheY2E6wWkISg7TtxJYgb/S0Zz7WruJzG
O9zxi7HTvuXyQr7QKSBtdCGmHym+WoPsbA==
-----END EC PRIVATE KEY-----
"""
        for index in simplePEM.indices.dropLast() {
            XCTAssertThrowsError(try ASN1.PEMDocument(pemString: String(simplePEM[..<index])),
                                 error: CryptoKitASN1Error.invalidPEMDocument)
        }

        XCTAssertNoThrow(try ASN1.PEMDocument(pemString: simplePEM))
    }

    func testMismatchedDiscriminatorsAreRejected() throws {
        // Different discriminators is not allowed.
        let simplePEM = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBHli4jaj+JwWQlU0yhZUu+TdMPVhZ3wR2PS416Sz/K/oAoGCCqGSM49
AwEHoUQDQgAEOhvJhbc3zM4SJooCaWdyheY2E6wWkISg7TtxJYgb/S0Zz7WruJzG
O9zxi7HTvuXyQr7QKSBtdCGmHym+WoPsbA==
-----END EC PUBLIC KEY-----
"""
        XCTAssertThrowsError(try ASN1.PEMDocument(pemString: simplePEM),
                             error: CryptoKitASN1Error.invalidPEMDocument)
    }

    func testOverlongLinesAreForbidden() throws {
        // This is arguably an excessive restriction, but we should try to be fairly strict here.
        let simplePEM = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBHli4jaj+JwWQlU0yhZUu+TdMPVhZ3wR2PS416Sz/K/oAoGCCqGSM49
AwEHoUQDQgAEOhvJhbc3zM4SJooCaWdyheY2E6wWkISg7TtxJYgb/S0Zz7WruJzGO
9zxi7HTvuXyQr7QKSBtdCGmHym+WoPsbA==
-----END EC PRIVATE KEY-----
"""
        XCTAssertThrowsError(try ASN1.PEMDocument(pemString: simplePEM),
                             error: CryptoKitASN1Error.invalidPEMDocument)
    }

    func testEarlyShortLinesAreForbidden() throws {
        // This is arguably an excessive restriction, but we should try to be fairly strict here.
        let simplePEM = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBHli4jaj+JwWQlU0yhZUu+TdMPVhZ3wR2PS416Sz/K/oAoGCCqGSM49
AwEHoUQDQgAEOhvJhbc3zM4SJooCaWdyheY2E6wWkISg7TtxJYgb/S0Zz7WruJz
GO9zxi7HTvuXyQr7QKSBtdCGmHym+WoPsbA==
-----END EC PRIVATE KEY-----
"""
        XCTAssertThrowsError(try ASN1.PEMDocument(pemString: simplePEM),
                             error: CryptoKitASN1Error.invalidPEMDocument)
    }

    func testEmptyPEMDocument() throws {
        let simplePEM = """
-----BEGIN EC PRIVATE KEY-----
-----END EC PRIVATE KEY-----
"""
        XCTAssertThrowsError(try ASN1.PEMDocument(pemString: simplePEM),
                             error: CryptoKitASN1Error.invalidPEMDocument)
    }

    func testInvalidBase64IsForbidden() throws {
        let simplePEM = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBHli4jaj+JwWQlU0yhZUu+TdMPVhZ3wR2PS416Sz/K/oAoGCCqGSM49
AwEHoUQDQgAEOhvJhbc3zM4SJooCaWdyheY2E6wWkISg7TtxJYgb/S0Zz7WruJzG
O9zxi7HTvuXyQr7QKSBtdC%mHym+WoPsbA==
-----END EC PRIVATE KEY-----
"""
        XCTAssertThrowsError(try ASN1.PEMDocument(pemString: simplePEM),
                             error: CryptoKitASN1Error.invalidPEMDocument)
    }

    func testRejectSingleComponentOIDs() throws {
        // This is an encoded OID that has only one subcomponent, 0.
        let singleComponentOID: [UInt8] = [0x06, 0x01, 0x00]
        let parsed = try ASN1.parse(singleComponentOID)
        XCTAssertThrowsError(try ASN1.ASN1ObjectIdentifier(asn1Encoded: parsed),
                             error: CryptoKitASN1Error.invalidObjectIdentifier)
    }

    func testRejectZeroComponentOIDs() throws {
        // This is an encoded OID that has no subcomponents..
        let zeroComponentOID: [UInt8] = [0x06, 0x00]
        let parsed = try ASN1.parse(zeroComponentOID)
        XCTAssertThrowsError(try ASN1.ASN1ObjectIdentifier(asn1Encoded: parsed),
                             error: CryptoKitASN1Error.invalidObjectIdentifier)
    }

    func testRejectNonOctetNumberOfBitsInBitstring() throws {
        // We don't allow bitstrings that have any number of bits in the bitstring that isn't a multiple of 8.
        for i in 1..<8 {
            let weirdBitString = [0x03, 0x02, UInt8(i), 0xFF]
            let parsed = try ASN1.parse(weirdBitString)
            XCTAssertThrowsError(try ASN1.ASN1BitString(asn1Encoded: parsed),
                                 error: CryptoKitASN1Error.invalidASN1Object)
        }
    }

    func testBitstringWithNoContent() throws {
        // We don't allow bitstrings with no content.
        let weirdBitString: [UInt8] = [0x03, 0x00]
        let parsed = try ASN1.parse(weirdBitString)
        XCTAssertThrowsError(try ASN1.ASN1BitString(asn1Encoded: parsed),
                             error: CryptoKitASN1Error.invalidASN1Object)
    }

    func testEmptyBitstring() throws {
        // Empty bitstrings must have their leading byte set to 0.
        var bitString: [UInt8] = [0x03, 0x01, 0x00]
        let parsed = try ASN1.parse(bitString)
        let bs = try ASN1.ASN1BitString(asn1Encoded: parsed)
        XCTAssertEqual(bs.bytes, [])

        for i in 1..<8 {
            bitString[2] = UInt8(i)
            let parsed = try ASN1.parse(bitString)
            XCTAssertThrowsError(try ASN1.ASN1BitString(asn1Encoded: parsed),
                                 error: CryptoKitASN1Error.invalidASN1Object)
        }
    }

    func testIntegerZeroRequiresAZeroByte() throws {
        // Integer zero requires a leading zero byte.
        let weirdZero: [UInt8] = [0x02, 0x00]
        let parsed = try ASN1.parse(weirdZero)
        XCTAssertThrowsError(try Int(asn1Encoded: parsed),
                             error: CryptoKitASN1Error.invalidASN1IntegerEncoding)
    }

    func testLeadingZero() throws {
        // We should reject integers that have unnecessary leading zero bytes.
        let overlongOne: [UInt8] = [0x02, 0x02, 0x00, 0x01]
        let parsed = try ASN1.parse(overlongOne)
        XCTAssertThrowsError(try Int(asn1Encoded: parsed),
                             error: CryptoKitASN1Error.invalidASN1IntegerEncoding)
    }

    func testLeadingOnes() throws {
        // We should reject integers that have unnecessary leading one bytes. This is supposed to be a -127, but we encode it as though it
        // were an Int16.
        let overlongOneTwoSeven: [UInt8] = [0x02, 0x02, 0xFF, 0x81]
        let parsed = try ASN1.parse(overlongOneTwoSeven)
        XCTAssertThrowsError(try Int(asn1Encoded: parsed),
                             error: CryptoKitASN1Error.invalidASN1IntegerEncoding)
    }

    func testNotConsumingTaggedObject() throws {
        // We should error if there are two nodes inside an explicitly tagged object.
        let weirdASN1: [UInt8] = [
            0x30, 0x08,       // Sequence, containing...
            0xA2, 0x06,       // Context specific tag 2, 3 byte body, containing...
            0x02, 0x01, 0x00, // Integer 0 and
            0x02, 0x01, 0x01  // Integer 1

        ]
        let parsed = try ASN1.parse(weirdASN1)
        try ASN1.sequence(parsed, identifier: .sequence) { nodes in
            XCTAssertThrowsError(try ASN1.optionalExplicitlyTagged(&nodes, tagNumber: 2, tagClass: .contextSpecific, { _ in }),
                                 error: CryptoKitASN1Error.invalidASN1Object)
        }
    }

    func testSPKIWithUnexpectedKeyTypeOID() throws {
        // This is an SPKI object for RSA instead of EC. This is a 1024-bit RSA key, so hopefully no-one will think to use it.
        let rsaSPKI = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDQEcP8qgwq5JhGgl1mKMeOWbb0WFKkJKj4Tvm4RFWGKDYg/p+Fm8vHwPSICqU9HJ+dHF2Ty0M6WVwVlf6RJdJGsrp1s9cbxfc/74PdQUssIhUjhlBO2RFlQECbgNpw5UleRB9FLnEDp33qMgdr7nwXiYCTjd04QSkdU3mXJYrFfwIDAQAB"
        let decodedSPKI = Array(Data(base64Encoded: rsaSPKI)!)

        var serializer = ASN1.Serializer()
        try serializer.appendPrimitiveNode(identifier: .null) { _ in }
        let null = serializer.serializedBytes

        let parsed = try ASN1.parse(decodedSPKI)
        let spki = try ASN1.SubjectPublicKeyInfo(asn1Encoded: parsed)
        XCTAssertEqual(spki.algorithmIdentifier.algorithm, [1, 2, 840, 113_549, 1, 1, 1])  // RSA encryption

        serializer = ASN1.Serializer()
        try serializer.serialize(spki.algorithmIdentifier.parameters!)
        XCTAssertEqual(serializer.serializedBytes, null)

        let expectedKey: ArraySlice<UInt8> = [
            48, 129, 137, 2, 129, 129, 0, 208, 17, 195, 252, 170, 12, 42, 228, 152,
            70, 130, 93, 102, 40, 199, 142, 89, 182, 244, 88, 82, 164, 36, 168, 248,
            78, 249, 184, 68, 85, 134, 40, 54, 32, 254, 159, 133, 155, 203, 199, 192,
            244, 136, 10, 165, 61, 28, 159, 157, 28, 93, 147, 203, 67, 58, 89, 92,
            21, 149, 254, 145, 37, 210, 70, 178, 186, 117, 179, 215, 27, 197, 247,
            63, 239, 131, 221, 65, 75, 44, 34, 21, 35, 134, 80, 78, 217, 17, 101, 64, 64, 155, 128, 218, 112, 229, 73, 94, 68, 31, 69, 46, 113, 3, 167, 125,
            234, 50, 7, 107, 238, 124, 23, 137, 128, 147, 141, 221, 56, 65, 41, 29,
            83, 121, 151, 37, 138, 197, 127, 2, 3, 1, 0, 1
        ]
        XCTAssertEqual(spki.key.bytes, expectedKey)
    }

    func testSPKIWithUnsupportedCurve() throws {
        // This is an EC SPKI object with an unsupported named curve.
        let b64SPKI = "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEzN09Sbb+mhMIlUbOdoIoND8lNcoQPd/yZDjQi1IDyDQEvVvz1yhi5J0FPLAlM3hE2o/a+rASUz2UP4fX5Cpnxw=="
        let decodedSPKI = Array(Data(base64Encoded: b64SPKI)!)

        let parsed = try ASN1.parse(decodedSPKI)
        let spki = try ASN1.SubjectPublicKeyInfo(asn1Encoded: parsed)
        XCTAssertEqual(spki.algorithmIdentifier.algorithm, .AlgorithmIdentifier.idEcPublicKey)
        XCTAssertEqual(try ASN1.ASN1ObjectIdentifier(asn1Any: spki.algorithmIdentifier.parameters!), [1, 3, 132, 0, 10])

        let expectedKey: ArraySlice<UInt8> = [
            4, 204, 221, 61, 73, 182, 254, 154, 19, 8, 149, 70, 206, 118, 130, 40,
            52, 63, 37, 53, 202, 16, 61, 223, 242, 100, 56, 208, 139, 82, 3, 200,
            52, 4, 189, 91, 243, 215, 40, 98, 228, 157, 5, 60, 176, 37, 51, 120, 68,
            218, 143, 218, 250, 176, 18, 83, 61, 148, 63, 135, 215, 228, 42, 103,
            199
        ]
        XCTAssertEqual(spki.key.bytes, expectedKey)
    }

    func testSEC1PrivateKeyWithUnknownVersion() throws {
        // This is the beginning of a SEC1 private key with hypothetical version number 5. We should reject it
        let weirdSEC1: [UInt8] = [0x30, 0x03, 0x02, 0x01, 0x05]

        let parsed = try ASN1.parse(weirdSEC1)
        XCTAssertThrowsError(try ASN1.SEC1PrivateKey(asn1Encoded: parsed), error: CryptoKitASN1Error.invalidASN1Object)
    }

    func testSEC1PrivateKeyUnsupportedKeyType() throws {
        // This is an EC SPKI object with an unsupported named curve.
        let b64SEC1 = "MHQCAQEEINIuVmNF7g1wNCJWXDpgL+09jATtaS1n0SxqqQneHi+woAcGBSuBBAAKoUQDQgAEB7v/p7gvuV0aDx02EF6a+pr563p+FzRJXI+COWHdr+XRcjg6vEi4n3Jj7ksmEg4t1x6E1xFyTvF3eV/B/XVXbw=="
        let decodedSEC1 = Array(Data(base64Encoded: b64SEC1)!)

        let parsed = try ASN1.parse(decodedSEC1)
        XCTAssertThrowsError(try ASN1.SEC1PrivateKey(asn1Encoded: parsed), error: CryptoKitASN1Error.invalidASN1Object)
    }

    func testPKCS8KeyWithNonMatchingKeyOIDS() throws {
        // This is a stubbed PKCS8 key with mismatched OIDs in the inner and outer payload. We have to serialize it out, sadly.
        var serializer = ASN1.Serializer()
        try serializer.appendConstructedNode(identifier: .sequence) { coder in
            try coder.serialize(0)
            try coder.serialize(ASN1.RFC5480AlgorithmIdentifier.ecdsaP256)

            var subCoder = ASN1.Serializer()
            try subCoder.serialize(ASN1.SEC1PrivateKey(privateKey: [], algorithm: .ecdsaP384, publicKey: []))  // We won't notice these are empty either, but we will notice the algo mismatch.
            let serializedKey = ASN1.ASN1OctetString(contentBytes: subCoder.serializedBytes[...])

            try coder.serialize(serializedKey)
        }

        let parsed = try ASN1.parse(serializer.serializedBytes)
        XCTAssertThrowsError(try ASN1.PKCS8PrivateKey(asn1Encoded: parsed), error: CryptoKitASN1Error.invalidASN1Object)
    }

    func testExcessiveDepth() throws {
        // This is an ASN1 document that has a deeply nested structure: Sequences within
        // Sequences, for eleven levels.
        let badASN1: [UInt8] = [
            0x30, 0x15, 0x30, 0x13, 0x30, 0x11, 0x30, 0x0f, 0x30, 0x0d,
            0x30, 0x0b, 0x30, 0x09, 0x30, 0x07, 0x30, 0x05, 0x30, 0x03,
            0x02, 0x01, 0x00  // Integer zero
        ]
        XCTAssertThrowsError(try ASN1.parse(badASN1)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidASN1Object)
        }
    }

    func testCanaryValuesOfFixedWidthIntegerEncoding() throws {
        // This test exercises integer encoding with all the stdlib fixed width integers, to confirm they work well.
        // We try four or five values for each: max, min, 0, and 1, as well as -1 for the signed integers.
        // This correctly validates that we know how to handle twos complement integers.
        func oneShotSerialize<T: FixedWidthInteger & ASN1IntegerRepresentable>(_ t: T) -> [UInt8] {
            var serializer = ASN1.Serializer()
            XCTAssertNoThrow(try serializer.serialize(t))
            return serializer.serializedBytes
        }

        XCTAssertEqual(oneShotSerialize(UInt8.max), [0x02, 0x02, 0x00, 0xFF])
        XCTAssertEqual(oneShotSerialize(UInt8.min), [0x02, 0x01, 0x00])
        XCTAssertEqual(oneShotSerialize(UInt8(0)), [0x02, 0x01, 0x00])
        XCTAssertEqual(oneShotSerialize(UInt8(1)), [0x02, 0x01, 0x01])

        XCTAssertEqual(oneShotSerialize(UInt16.max), [0x02, 0x03, 0x00, 0xFF, 0xFF])
        XCTAssertEqual(oneShotSerialize(UInt16.min), [0x02, 0x01, 0x00])
        XCTAssertEqual(oneShotSerialize(UInt16(0)), [0x02, 0x01, 0x00])
        XCTAssertEqual(oneShotSerialize(UInt16(1)), [0x02, 0x01, 0x01])

        XCTAssertEqual(oneShotSerialize(UInt32.max), [0x02, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF])
        XCTAssertEqual(oneShotSerialize(UInt32.min), [0x02, 0x01, 0x00])
        XCTAssertEqual(oneShotSerialize(UInt32(0)), [0x02, 0x01, 0x00])
        XCTAssertEqual(oneShotSerialize(UInt32(1)), [0x02, 0x01, 0x01])

        XCTAssertEqual(oneShotSerialize(UInt64.max), [0x02, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        XCTAssertEqual(oneShotSerialize(UInt64.min), [0x02, 0x01, 0x00])
        XCTAssertEqual(oneShotSerialize(UInt64(0)), [0x02, 0x01, 0x00])
        XCTAssertEqual(oneShotSerialize(UInt64(1)), [0x02, 0x01, 0x01])

        XCTAssertEqual(oneShotSerialize(Int8.max), [0x02, 0x01, 0x7F])
        XCTAssertEqual(oneShotSerialize(Int8.min), [0x02, 0x01, 0x80])
        XCTAssertEqual(oneShotSerialize(Int8(0)), [0x02, 0x01, 0x00])
        XCTAssertEqual(oneShotSerialize(Int8(1)), [0x02, 0x01, 0x01])
        XCTAssertEqual(oneShotSerialize(Int8(-1)), [0x02, 0x01, 0xFF])

        XCTAssertEqual(oneShotSerialize(Int16.max), [0x02, 0x02, 0x7F, 0xFF])
        XCTAssertEqual(oneShotSerialize(Int16.min), [0x02, 0x02, 0x80, 0x00])
        XCTAssertEqual(oneShotSerialize(Int16(0)), [0x02, 0x01, 0x00])
        XCTAssertEqual(oneShotSerialize(Int16(1)), [0x02, 0x01, 0x01])
        XCTAssertEqual(oneShotSerialize(Int16(-1)), [0x02, 0x01, 0xFF])

        XCTAssertEqual(oneShotSerialize(Int32.max), [0x02, 0x04, 0x7F, 0xFF, 0xFF, 0xFF])
        XCTAssertEqual(oneShotSerialize(Int32.min), [0x02, 0x04, 0x80, 0x00, 0x00, 0x00])
        XCTAssertEqual(oneShotSerialize(Int32(0)), [0x02, 0x01, 0x00])
        XCTAssertEqual(oneShotSerialize(Int32(1)), [0x02, 0x01, 0x01])
        XCTAssertEqual(oneShotSerialize(Int32(-1)), [0x02, 0x01, 0xFF])

        XCTAssertEqual(oneShotSerialize(Int64.max), [0x02, 0x08, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        XCTAssertEqual(oneShotSerialize(Int64.min), [0x02, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        XCTAssertEqual(oneShotSerialize(Int64(0)), [0x02, 0x01, 0x00])
        XCTAssertEqual(oneShotSerialize(Int64(1)), [0x02, 0x01, 0x01])
        XCTAssertEqual(oneShotSerialize(Int64(-1)), [0x02, 0x01, 0xFF])
    }

    func testCanaryValuesOfFixedWidthIntegerDecoding() throws {
        // This test exercises integer decoding with all the stdlib fixed width integers, to confirm they work well.
        // We try four or five values for each: max, min, 0, and 1, as well as -1 for the signed integers.
        // This correctly validates that we know how to handle twos complement integers.
        func oneShotDecode<T: FixedWidthInteger & ASN1IntegerRepresentable>(_ bytes: [UInt8]) throws -> T {
            let baseNode = try orFail { try ASN1.parse(bytes) }
            return try orFail { try T(asn1Encoded: baseNode) }
        }

        XCTAssertEqual(UInt8.max, try oneShotDecode([0x02, 0x02, 0x00, 0xFF]))
        XCTAssertEqual(UInt8.min, try oneShotDecode([0x02, 0x01, 0x00]))
        XCTAssertEqual(UInt8(0), try oneShotDecode([0x02, 0x01, 0x00]))
        XCTAssertEqual(UInt8(1), try oneShotDecode([0x02, 0x01, 0x01]))

        XCTAssertEqual(UInt16.max, try oneShotDecode([0x02, 0x03, 0x00, 0xFF, 0xFF]))
        XCTAssertEqual(UInt16.min, try oneShotDecode([0x02, 0x01, 0x00]))
        XCTAssertEqual(UInt16(0), try oneShotDecode([0x02, 0x01, 0x00]))
        XCTAssertEqual(UInt16(1), try oneShotDecode([0x02, 0x01, 0x01]))

        XCTAssertEqual(UInt32.max, try oneShotDecode([0x02, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]))
        XCTAssertEqual(UInt32.min, try oneShotDecode([0x02, 0x01, 0x00]))
        XCTAssertEqual(UInt32(0), try oneShotDecode([0x02, 0x01, 0x00]))
        XCTAssertEqual(UInt32(1), try oneShotDecode([0x02, 0x01, 0x01]))

        XCTAssertEqual(UInt64.max, try oneShotDecode([0x02, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]))
        XCTAssertEqual(UInt64.min, try oneShotDecode([0x02, 0x01, 0x00]))
        XCTAssertEqual(UInt64(0), try oneShotDecode([0x02, 0x01, 0x00]))
        XCTAssertEqual(UInt64(1), try oneShotDecode([0x02, 0x01, 0x01]))

        XCTAssertEqual(Int8.max, try oneShotDecode([0x02, 0x01, 0x7F]))
        XCTAssertEqual(Int8.min, try oneShotDecode([0x02, 0x01, 0x80]))
        XCTAssertEqual(Int8(0), try oneShotDecode([0x02, 0x01, 0x00]))
        XCTAssertEqual(Int8(1), try oneShotDecode([0x02, 0x01, 0x01]))
        XCTAssertEqual(Int8(-1), try oneShotDecode([0x02, 0x01, 0xFF]))

        XCTAssertEqual(Int16.max, try oneShotDecode([0x02, 0x02, 0x7F, 0xFF]))
        XCTAssertEqual(Int16.min, try oneShotDecode([0x02, 0x02, 0x80, 0x00]))
        XCTAssertEqual(Int16(0), try oneShotDecode([0x02, 0x01, 0x00]))
        XCTAssertEqual(Int16(1), try oneShotDecode([0x02, 0x01, 0x01]))
        XCTAssertEqual(Int16(-1), try oneShotDecode([0x02, 0x01, 0xFF]))

        XCTAssertEqual(Int32.max, try oneShotDecode([0x02, 0x04, 0x7F, 0xFF, 0xFF, 0xFF]))
        XCTAssertEqual(Int32.min, try oneShotDecode([0x02, 0x04, 0x80, 0x00, 0x00, 0x00]))
        XCTAssertEqual(Int32(0), try oneShotDecode([0x02, 0x01, 0x00]))
        XCTAssertEqual(Int32(1), try oneShotDecode([0x02, 0x01, 0x01]))
        XCTAssertEqual(Int32(-1), try oneShotDecode([0x02, 0x01, 0xFF]))

        XCTAssertEqual(Int64.max, try oneShotDecode([0x02, 0x08, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]))
        XCTAssertEqual(Int64.min, try oneShotDecode([0x02, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
        XCTAssertEqual(Int64(0), try oneShotDecode([0x02, 0x01, 0x00]))
        XCTAssertEqual(Int64(1), try oneShotDecode([0x02, 0x01, 0x01]))
        XCTAssertEqual(Int64(-1), try oneShotDecode([0x02, 0x01, 0xFF]))
    }

    func testWeirdBigIntSerialization() throws {
        // This is a bigint we can hook to get the test function to do weird things.
        // We just take and accept arbitrary bytes.
        struct BigIntOfBytes: ASN1IntegerRepresentable, Equatable {
            var bytes: [UInt8]

            static let isSigned: Bool = false

            init(bytes: [UInt8]) {
                self.bytes = bytes
            }

            init(asn1IntegerBytes: ArraySlice<UInt8>) {
                self.bytes = Array(asn1IntegerBytes)
            }

            func withBigEndianIntegerBytes<ReturnType>(_ body: ([UInt8]) throws -> ReturnType) rethrows -> ReturnType {
                return try body(self.bytes)
            }
        }

        func oneShotSerialize(_ t: BigIntOfBytes) -> [UInt8] {
            var serializer = ASN1.Serializer()
            XCTAssertNoThrow(try serializer.serialize(t))
            return serializer.serializedBytes
        }

        func oneShotDecode(_ bytes: [UInt8]) throws -> BigIntOfBytes {
            let baseNode = try orFail { try ASN1.parse(bytes) }
            return try orFail { try BigIntOfBytes(asn1Encoded: baseNode) }
        }

        // Leading zero bytes should be stripped.
        let leadingZeros = BigIntOfBytes(bytes: [0, 0, 0, 0, 1])
        XCTAssertEqual(oneShotSerialize(leadingZeros), [0x02, 0x01, 0x01])

        // Except when they are guarding a 1 in the next byte.
        let fakeOutLeadingZeros = BigIntOfBytes(bytes: [0x00, 0x00, 0x80])
        XCTAssertEqual(oneShotSerialize(fakeOutLeadingZeros), [0x02, 0x02, 0x00, 0x80])

        // And a leading zero is removed for unsigned bigints.
        let leadingZeroFromWire = try oneShotDecode([0x02, 0x02, 0x00, 0x80])
        XCTAssertEqual(leadingZeroFromWire.bytes, [0x80])

        // Check encoding and decoding results should be same
        let smallBytes = BigIntOfBytes(bytes: [1, 1, 1])
        XCTAssertEqual(smallBytes, try oneShotDecode(oneShotSerialize(smallBytes)))

        let largeBytes = BigIntOfBytes(bytes: .init(repeating: 1, count: 1024))
        XCTAssertEqual(largeBytes, try oneShotDecode(oneShotSerialize(largeBytes)))
    }
}

#endif
