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
import XCTest

#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// Skip tests that require @testable imports of CryptoKit.
#else
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@testable import CryptoKit
#else
@testable import Crypto
#endif

class ASN1Tests: XCTestCase {
    func testSimpleASN1P256SPKI() throws {
        // Given a static SPKI structure, verifies the parse.
        let encodedSPKI = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2adMrdG7aUfZH57aeKFFM01dPnkxC18ScRb4Z6poMBgJtYlVtd9ly63URv57ZW0Ncs1LiZB7WATb3svu+1c7HQ=="
        let decodedSPKI = Array(Data(base64Encoded: encodedSPKI)!)

        let result = try orFail { try ASN1.parse(decodedSPKI) }
        let spki = try orFail { try ASN1.SubjectPublicKeyInfo(asn1Encoded: result) }

        XCTAssertEqual(spki.algorithmIdentifier, .ecdsaP256)
        XCTAssertNoThrow(try P256.Signing.PublicKey(x963Representation: spki.key))
        XCTAssertNoThrow(try P256.KeyAgreement.PublicKey(x963Representation: spki.key))

        // For SPKI we should be able to round-trip the serialization.
        var serializer = ASN1.Serializer()
        XCTAssertNoThrow(try serializer.serialize(spki))
        XCTAssertEqual(serializer.serializedBytes, decodedSPKI)
    }

    func testSimpleASN1P384SPKI() throws {
        let encodedSPKI = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEcBr0TNmgagf1ysckEA/3XLGx2amgzeHjDBZREqhCIVBrLhIiIR4zrJ8dqad/Y+zI2Hu8TIUbrzS/diFpFoE0YYKBTfYMCAUtaWuMb1oaBdFzWsLfYSSzF+ON1yeJCtro"
        let decodedSPKI = Array(Data(base64Encoded: encodedSPKI)!)

        let result = try orFail { try ASN1.parse(decodedSPKI) }
        let spki = try orFail { try ASN1.SubjectPublicKeyInfo(asn1Encoded: result) }

        XCTAssertEqual(spki.algorithmIdentifier, .ecdsaP384)
        XCTAssertNoThrow(try P384.Signing.PublicKey(x963Representation: spki.key))
        XCTAssertNoThrow(try P384.KeyAgreement.PublicKey(x963Representation: spki.key))

        // For SPKI we should be able to round-trip the serialization.
        var serializer = ASN1.Serializer()
        XCTAssertNoThrow(try serializer.serialize(spki))
        XCTAssertEqual(serializer.serializedBytes, decodedSPKI)
    }

    func testSimpleASN1P521SPKI() throws {
        let encodedSPKI = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBTxMJZTRr9NcKmD7iTeX7ofcgz77JPTIDXOHFfS1tZHd9P0uAeK/ARwwDdsQpIKCvmtaO4O52oHqmczdrRwGtrHIBUTqaOw2Fqdiqt0fRQju9wH1Xi4h8u0h80MymUM0sbAQ70jHCeV0S0mGcJS8t3nfP+qLes30h297dPfV3SLsLg8M="
        let decodedSPKI = Array(Data(base64Encoded: encodedSPKI)!)

        let result = try orFail { try ASN1.parse(decodedSPKI) }
        let spki = try orFail { try ASN1.SubjectPublicKeyInfo(asn1Encoded: result) }

        XCTAssertEqual(spki.algorithmIdentifier, .ecdsaP521)
        XCTAssertNoThrow(try P521.Signing.PublicKey(x963Representation: spki.key))
        XCTAssertNoThrow(try P521.KeyAgreement.PublicKey(x963Representation: spki.key))

        // For SPKI we should be able to round-trip the serialization.
        var serializer = ASN1.Serializer()
        XCTAssertNoThrow(try serializer.serialize(spki))
        XCTAssertEqual(serializer.serializedBytes, decodedSPKI)
    }

    func testASN1SEC1PrivateKeyP256() throws {
        let encodedPrivateKey = "MHcCAQEEIFAV2+taX2/ht9HEcLQPtfyuRktTkn4S3RaCQwDmDnrloAoGCCqGSM49AwEHoUQDQgAE3Oed98X0hHmzHmmmgtf5rAVEv0jIeH61K61P5UyiCozn+fz+mlmBywvluiVvERiT9WZCd3tkPPWwbIr+a0dnwA=="
        let decodedPrivateKey = Array(Data(base64Encoded: encodedPrivateKey)!)

        let result = try orFail { try ASN1.parse(decodedPrivateKey) }
        let pkey = try orFail { try ASN1.SEC1PrivateKey(asn1Encoded: result) }

        XCTAssertEqual(pkey.algorithm, .ecdsaP256)
        let privateKey = try orFail { try P256.Signing.PrivateKey(rawRepresentation: pkey.privateKey) }
        let publicKey = try orFail { try P256.Signing.PublicKey(x963Representation: pkey.publicKey!) }
        XCTAssertEqual(privateKey.publicKey.rawRepresentation, publicKey.rawRepresentation)

        let kexPrivateKey = try orFail { try P256.KeyAgreement.PrivateKey(rawRepresentation: pkey.privateKey) }
        let kexPublicKey = try orFail { try P256.KeyAgreement.PublicKey(x963Representation: pkey.publicKey!) }
        XCTAssertEqual(kexPrivateKey.publicKey.rawRepresentation, kexPublicKey.rawRepresentation)

        // For SEC1 we should be able to round-trip the serialization.
        var serializer = ASN1.Serializer()
        XCTAssertNoThrow(try serializer.serialize(pkey))
        XCTAssertEqual(serializer.serializedBytes, decodedPrivateKey)
    }

    func testASN1SEC1PrivateKeyP384() throws {
        let encodedPrivateKey = "MIGkAgEBBDAWv9iH6ZivZKtk5ihjvjlZCYc9JHyykqvmJ7JVQ50ZZWTkCPtIe7RSKzm+l7NJltqgBwYFK4EEACKhZANiAAQz0BBmMxeOj5XwTL1G4fqTYO2UAiYrUMixiRFlFKVY5I6jAgiEWdNbmte8o6dByo0No5YoyDHdG637xvuzGaWd+IT5LoBAVVv3AgL3ao3dA4aVhm6Yz6G6/2o3X7AH99c="
        let decodedPrivateKey = Array(Data(base64Encoded: encodedPrivateKey)!)

        let result = try orFail { try ASN1.parse(decodedPrivateKey) }
        let pkey = try orFail { try ASN1.SEC1PrivateKey(asn1Encoded: result) }

        XCTAssertEqual(pkey.algorithm, .ecdsaP384)
        let privateKey = try orFail { try P384.Signing.PrivateKey(rawRepresentation: pkey.privateKey) }
        let publicKey = try orFail { try P384.Signing.PublicKey(x963Representation: pkey.publicKey!) }
        XCTAssertEqual(privateKey.publicKey.rawRepresentation, publicKey.rawRepresentation)

        let kexPrivateKey = try orFail { try P384.KeyAgreement.PrivateKey(rawRepresentation: pkey.privateKey) }
        let kexPublicKey = try orFail { try P384.KeyAgreement.PublicKey(x963Representation: pkey.publicKey!) }
        XCTAssertEqual(kexPrivateKey.publicKey.rawRepresentation, kexPublicKey.rawRepresentation)

        // For SEC1 we should be able to round-trip the serialization.
        var serializer = ASN1.Serializer()
        XCTAssertNoThrow(try serializer.serialize(pkey))
        XCTAssertEqual(serializer.serializedBytes, decodedPrivateKey)
    }

    func testASN1SEC1PrivateKeyP521() throws {
        let encodedPrivateKey = "MIHcAgEBBEIBONszidL11f7D8LEbVGKG4A7768X16w35/m6OSPO7MGQcYhWHpgSV4NZ6AFKcksavZSCa59lYdAN+MA3sUjO7R/mgBwYFK4EEACOhgYkDgYYABAAzsbWlHXjMkaSQTBnBKcyPDy/x0nk+VlkYQJXkh+lPJSVEYLbrUZ1LdbfM9mGE7HpgyyELNRHy/BD1JdNnAVPemAC5VQjeGKbezrxz7D5iZNiZiQFVYtMBU3XSsuJrPWVSjBF7xIkOr06k2xg1qlOoXQ66EPHQlwEYJ3xATNKk8K2jlQ=="
        let decodedPrivateKey = Array(Data(base64Encoded: encodedPrivateKey)!)

        let result = try orFail { try ASN1.parse(decodedPrivateKey) }
        let pkey = try orFail { try ASN1.SEC1PrivateKey(asn1Encoded: result) }

        XCTAssertEqual(pkey.algorithm, .ecdsaP521)
        let privateKey = try orFail { try P521.Signing.PrivateKey(rawRepresentation: pkey.privateKey) }
        let publicKey = try orFail { try P521.Signing.PublicKey(x963Representation: pkey.publicKey!) }
        XCTAssertEqual(privateKey.publicKey.rawRepresentation, publicKey.rawRepresentation)

        let kexPrivateKey = try orFail { try P521.KeyAgreement.PrivateKey(rawRepresentation: pkey.privateKey) }
        let kexPublicKey = try orFail { try P521.KeyAgreement.PublicKey(x963Representation: pkey.publicKey!) }
        XCTAssertEqual(kexPrivateKey.publicKey.rawRepresentation, kexPublicKey.rawRepresentation)

        // For SEC1 we should be able to round-trip the serialization.
        var serializer = ASN1.Serializer()
        XCTAssertNoThrow(try serializer.serialize(pkey))
        XCTAssertEqual(serializer.serializedBytes, decodedPrivateKey)
    }

    func testASN1PKCS8PrivateKeyP256() throws {
        let encodedPrivateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCRQo0CoBKfTOhdgQHcQIVv21vIUsxmE3t9L1LqV00bahRANCAATDXEj3jviAtzgx4bnMa/081v+FXbp7O5D1KtKVdje+ckejGVLYuYKE4Lpf5jonefi6wtoCc/sWHlbLiNV5PEB9"
        let decodedPrivateKey = Array(Data(base64Encoded: encodedPrivateKey)!)

        let result = try orFail { try ASN1.parse(decodedPrivateKey) }
        let pkey = try orFail { try ASN1.PKCS8PrivateKey(asn1Encoded: result) }

        XCTAssertEqual(pkey.algorithm, .ecdsaP256)
        XCTAssertNil(pkey.privateKey.algorithm)  // OpenSSL nils this out for some reason
        let privateKey = try orFail { try P256.Signing.PrivateKey(rawRepresentation: pkey.privateKey.privateKey) }
        let publicKey = try orFail { try P256.Signing.PublicKey(x963Representation: pkey.privateKey.publicKey!) }
        XCTAssertEqual(privateKey.publicKey.rawRepresentation, publicKey.rawRepresentation)

        let kexPrivateKey = try orFail { try P256.KeyAgreement.PrivateKey(rawRepresentation: pkey.privateKey.privateKey) }
        let kexPublicKey = try orFail { try P256.KeyAgreement.PublicKey(x963Representation: pkey.privateKey.publicKey!) }
        XCTAssertEqual(kexPrivateKey.publicKey.rawRepresentation, kexPublicKey.rawRepresentation)

        // For PKCS8 we should be able to round-trip the serialization.
        var serializer = ASN1.Serializer()
        XCTAssertNoThrow(try serializer.serialize(pkey))
        XCTAssertEqual(serializer.serializedBytes, decodedPrivateKey)
    }

    func testASN1PKCS8PrivateKeyP384() throws {
        let encodedPrivateKey = "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCKfeRAkTtGQG7bGao6Ca5MDDcmxttyr6HNmNoaSkmuYvBtLGLLBWm1+VHT602xOIihZANiAAS56RzXiLO5YvFI0qh/+T9DhOXfkm3K/jJSUAqV/hP0FUlIUR824cFVdMMQA1S100mETsxdT0QDqUGAinMTUBSyk9y+jR33Fw/A068ZQRlqTCa0ThS0vwxKhM/M4vhYeDE="
        let decodedPrivateKey = Array(Data(base64Encoded: encodedPrivateKey)!)

        let result = try orFail { try ASN1.parse(decodedPrivateKey) }
        let pkey = try orFail { try ASN1.PKCS8PrivateKey(asn1Encoded: result) }

        XCTAssertEqual(pkey.algorithm, .ecdsaP384)
        XCTAssertNil(pkey.privateKey.algorithm)  // OpenSSL nils this out for some reason
        let privateKey = try orFail { try P384.Signing.PrivateKey(rawRepresentation: pkey.privateKey.privateKey) }
        let publicKey = try orFail { try P384.Signing.PublicKey(x963Representation: pkey.privateKey.publicKey!) }
        XCTAssertEqual(privateKey.publicKey.rawRepresentation, publicKey.rawRepresentation)

        let kexPrivateKey = try orFail { try P384.KeyAgreement.PrivateKey(rawRepresentation: pkey.privateKey.privateKey) }
        let kexPublicKey = try orFail { try P384.KeyAgreement.PublicKey(x963Representation: pkey.privateKey.publicKey!) }
        XCTAssertEqual(kexPrivateKey.publicKey.rawRepresentation, kexPublicKey.rawRepresentation)

        // For PKCS8 we should be able to round-trip the serialization.
        var serializer = ASN1.Serializer()
        XCTAssertNoThrow(try serializer.serialize(pkey))
        XCTAssertEqual(serializer.serializedBytes, decodedPrivateKey)
    }

    func testASN1PKCS8PrivateKeyP521() throws {
        let encodedPrivateKey = "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB/rwbfr3a+rdHQvKToS6Fw1WxsVFy3Wq2ylWC+EyQv//nGiT5TQYIAV2WDmmud3WnczITapXAAe6eS66jHa+OxyGhgYkDgYYABADrY6IBU4t8BjSIvDWA4VrLILdUOFemM2G8phpJWlGpEO8Qmk28w5pdLD2j3chBvg0xBBi2k9Ked9L43R4E3+gPCAA3CY8v01xlA6npJvdAK0/Md4mY+p65Ehua95jXnSwrpF66+Q/se2ODvZPhXGKBvttxrKyBr9htmkAUv9Sdah+dWQ=="
        let decodedPrivateKey = Array(Data(base64Encoded: encodedPrivateKey)!)

        let result = try orFail { try ASN1.parse(decodedPrivateKey) }
        let pkey = try orFail { try ASN1.PKCS8PrivateKey(asn1Encoded: result) }

        XCTAssertEqual(pkey.algorithm, .ecdsaP521)
        XCTAssertNil(pkey.privateKey.algorithm)  // OpenSSL nils this out for some reason
        let privateKey = try orFail { try P521.Signing.PrivateKey(rawRepresentation: pkey.privateKey.privateKey) }
        let publicKey = try orFail { try P521.Signing.PublicKey(x963Representation: pkey.privateKey.publicKey!) }
        XCTAssertEqual(privateKey.publicKey.rawRepresentation, publicKey.rawRepresentation)

        let kexPrivateKey = try orFail { try P521.KeyAgreement.PrivateKey(rawRepresentation: pkey.privateKey.privateKey) }
        let kexPublicKey = try orFail { try P521.KeyAgreement.PublicKey(x963Representation: pkey.privateKey.publicKey!) }
        XCTAssertEqual(kexPrivateKey.publicKey.rawRepresentation, kexPublicKey.rawRepresentation)

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
        let parsed = try orFail { try ASN1.parse(decodedReal) }

        XCTAssertThrowsError(try ASN1.ASN1ObjectIdentifier(asn1Encoded: parsed)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try ASN1.sequence(parsed, { _ in })) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try ASN1.ASN1OctetString(asn1Encoded: parsed)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try ASN1.ASN1BitString(asn1Encoded: parsed)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try Int(asn1Encoded: parsed)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
    }

    func testMultipleRootNodesAreForbidden() throws {
        // This is an ASN.1 REAL, a type we don't support, repeated
        let base64Node = "CQUDMUUtMQkFAzFFLTE="
        let decodedReal = Array(Data(base64Encoded: base64Node)!)
        XCTAssertThrowsError(try ASN1.parse(decodedReal)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidASN1Object)
        }
    }

    func testTrailingBytesAreForbidden() throws {
        // This is an ASN.1 INTEGER with trailing junk bytes
        let base64Node = "AgEBAA=="
        let decodedInteger = Array(Data(base64Encoded: base64Node)!)
        XCTAssertThrowsError(try ASN1.parse(decodedInteger)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidASN1Object)
        }
    }

    func testEmptyStringsDontDecode() throws {
        XCTAssertThrowsError(try ASN1.parse([])) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .truncatedASN1Field)
        }
    }

    func testRejectMultibyteTag() throws {
        // This is an ASN.1 INTEGER with a multibyte explicit tag, with the raw numerical value being 55.
        let base64Node = "vzcDAgEB"
        let decodedInteger = Array(Data(base64Encoded: base64Node)!)
        XCTAssertThrowsError(try ASN1.parse(decodedInteger)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidFieldIdentifier)
        }
    }

    func testSequenceMustConsumeAllNodes() throws {
        // This is an ASN.1 SEQUENCE with two child nodes, both octet strings. We're going to consume only one.
        let base64Sequence = "MAwEBEFCQ0QEBEVGR0g="
        let decodedSequence = Array(Data(base64Encoded: base64Sequence)!)
        let parsed = try orFail { try ASN1.parse(decodedSequence) }

        do {
            try ASN1.sequence(parsed) { nodes in
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
        let parsed = try orFail { try ASN1.parse(decodedSequence) }

        do {
            try ASN1.sequence(parsed) { nodes in
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
        XCTAssertThrowsError(try ASN1.parse([0xe7, 0x80])) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unsupportedFieldLength)
        }
    }

    func testRejectsUnterminatedASN1OIDSubidentifiers() throws {
        // This data contains the ASN.1 OID 2.6.7, with the last subidentifier having been mangled to set the top bit.
        // This makes it look like we're expecting more data in the OID, and we should flag it as truncated.
        let badBase64 = "BgJWhw=="
        let badNode = Array(Data(base64Encoded: badBase64)!)
        let parsed = try orFail { try ASN1.parse(badNode) }

        XCTAssertThrowsError(try ASN1.ASN1ObjectIdentifier(asn1Encoded: parsed)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidASN1Object)
        }
    }

    func testRejectsMassiveIntegers() throws {
        // This is an ASN.1 integer containing UInt64.max * 2. This is too big for us to store, and we reject it.
        // This test may need to be rewritten if we either support arbitrary integers or move to platforms where
        // UInt is larger than 64 bits (seems unlikely).
        let badBase64 = "AgkB//////////4="
        let badNode = Array(Data(base64Encoded: badBase64)!)
        let parsed = try orFail { try ASN1.parse(badNode) }

        XCTAssertThrowsError(try Int(asn1Encoded: parsed)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidASN1Object)
        }
    }

    func testStraightforwardPEMParsing() throws {
        let simplePEM = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBHli4jaj+JwWQlU0yhZUu+TdMPVhZ3wR2PS416Sz/K/oAoGCCqGSM49
AwEHoUQDQgAEOhvJhbc3zM4SJooCaWdyheY2E6wWkISg7TtxJYgb/S0Zz7WruJzG
O9zxi7HTvuXyQr7QKSBtdCGmHym+WoPsbA==
-----END EC PRIVATE KEY-----
"""
        let document = try orFail { try ASN1.PEMDocument(pemString: simplePEM) }
        XCTAssertEqual(document.type, "EC PRIVATE KEY")
        XCTAssertEqual(document.derBytes.count, 121)

        let parsed = try orFail { try ASN1.parse(Array(document.derBytes)) }
        let pkey = try orFail { try ASN1.SEC1PrivateKey(asn1Encoded: parsed) }

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
            XCTAssertThrowsError(try ASN1.PEMDocument(pemString: String(simplePEM[..<index]))) { error in
                XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
            }
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
        XCTAssertThrowsError(try ASN1.PEMDocument(pemString: simplePEM)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
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
        XCTAssertThrowsError(try ASN1.PEMDocument(pemString: simplePEM)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
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
        XCTAssertThrowsError(try ASN1.PEMDocument(pemString: simplePEM)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
    }

    func testEmptyPEMDocument() throws {
        let simplePEM = """
-----BEGIN EC PRIVATE KEY-----
-----END EC PRIVATE KEY-----
"""
        XCTAssertThrowsError(try ASN1.PEMDocument(pemString: simplePEM)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
    }

    func testInvalidBase64IsForbidden() throws {
        let simplePEM = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBHli4jaj+JwWQlU0yhZUu+TdMPVhZ3wR2PS416Sz/K/oAoGCCqGSM49
AwEHoUQDQgAEOhvJhbc3zM4SJooCaWdyheY2E6wWkISg7TtxJYgb/S0Zz7WruJzG
O9zxi7HTvuXyQr7QKSBtdC%mHym+WoPsbA==
-----END EC PRIVATE KEY-----
"""
        XCTAssertThrowsError(try ASN1.PEMDocument(pemString: simplePEM)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
    }

    func testRejectSingleComponentOIDs() throws {
        // This is an encoded OID that has only one subcomponent, 0.
        let singleComponentOID: [UInt8] = [0x06, 0x01, 0x00]
        let parsed = try orFail { try ASN1.parse(singleComponentOID) }
        XCTAssertThrowsError(try ASN1.ASN1ObjectIdentifier(asn1Encoded: parsed)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidObjectIdentifier)
        }
    }

    func testRejectZeroComponentOIDs() throws {
        // This is an encoded OID that has no subcomponents..
        let zeroComponentOID: [UInt8] = [0x06, 0x00]
        let parsed = try orFail { try ASN1.parse(zeroComponentOID) }
        XCTAssertThrowsError(try ASN1.ASN1ObjectIdentifier(asn1Encoded: parsed)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidObjectIdentifier)
        }
    }

    func testRejectNonOctetNumberOfBitsInBitstring() throws {
        // We don't allow bitstrings that have any number of bits in the bitstring that isn't a multiple of 8.
        for i in 1..<8 {
            let weirdBitString = [0x03, 0x02, UInt8(i), 0xFF]
            let parsed = try orFail { try ASN1.parse(weirdBitString) }
            XCTAssertThrowsError(try ASN1.ASN1BitString(asn1Encoded: parsed)) { error in
                XCTAssertEqual(error as? CryptoKitASN1Error, .invalidASN1Object)
            }
        }
    }

    func testBitstringWithNoContent() throws {
        // We don't allow bitstrings with no content.
        let weirdBitString: [UInt8] = [0x03, 0x00]
        let parsed = try orFail { try ASN1.parse(weirdBitString) }
        XCTAssertThrowsError(try ASN1.ASN1BitString(asn1Encoded: parsed)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidASN1Object)
        }
    }

    func testEmptyBitstring() throws {
        // Empty bitstrings must have their leading byte set to 0.
        var bitString: [UInt8] = [0x03, 0x01, 0x00]
        let parsed = try orFail { try ASN1.parse(bitString) }
        let bs = try orFail { try ASN1.ASN1BitString(asn1Encoded: parsed) }
        XCTAssertEqual(bs.bytes, [])

        for i in 1..<8 {
            bitString[2] = UInt8(i)
            let parsed = try orFail { try ASN1.parse(bitString) }
            XCTAssertThrowsError(try ASN1.ASN1BitString(asn1Encoded: parsed)) { error in
                XCTAssertEqual(error as? CryptoKitASN1Error, .invalidASN1Object)
            }
        }
    }

    func testIntegerZeroRequiresAZeroByte() throws {
        // Integer zero requires a leading zero byte.
        let weirdZero: [UInt8] = [0x02, 0x00]
        let parsed = try orFail { try ASN1.parse(weirdZero) }
        XCTAssertThrowsError(try Int(asn1Encoded: parsed)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidASN1IntegerEncoding)
        }
    }

    func testLeadingZero() throws {
        // We should reject integers that have unnecessary leading zero bytes.
        let overlongOne: [UInt8] = [0x02, 0x02, 0x00, 0x01]
        let parsed = try orFail { try ASN1.parse(overlongOne) }
        XCTAssertThrowsError(try Int(asn1Encoded: parsed)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidASN1IntegerEncoding)
        }
    }

    func testLeadingOnes() throws {
        // We should reject integers that have unnecessary leading one bytes. This is supposed to be a -127, but we encode it as though it
        // were an Int16.
        let overlongOneTwoSeven: [UInt8] = [0x02, 0x02, 0xFF, 0x81]
        let parsed = try orFail { try ASN1.parse(overlongOneTwoSeven) }
        XCTAssertThrowsError(try Int(asn1Encoded: parsed)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidASN1IntegerEncoding)
        }
    }

    func testNotConsumingTaggedObject() throws {
        // We should error if there are two nodes inside an explicitly tagged object.
        let weirdASN1: [UInt8] = [
            0x30, 0x08,       // Sequence, containing...
            0xA2, 0x06,       // Context specific tag 2, 3 byte body, containing...
            0x02, 0x01, 0x00, // Integer 0 and
            0x02, 0x01, 0x01  // Integer 1

        ]
        let parsed = try orFail { try ASN1.parse(weirdASN1) }
        try ASN1.sequence(parsed) { nodes in
            XCTAssertThrowsError(try ASN1.optionalExplicitlyTagged(&nodes, tagNumber: 2, tagClass: .contextSpecific, { _ in })) { error in
                XCTAssertEqual(error as? CryptoKitASN1Error, .invalidASN1Object)
            }
        }
    }

    func testSPKIWithUnexpectedKeyTypeOID() throws {
        // This is an SPKI object for RSA instead of EC. This is a 1024-bit RSA key, so hopefully no-one will think to use it.
        let rsaSPKI = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDQEcP8qgwq5JhGgl1mKMeOWbb0WFKkJKj4Tvm4RFWGKDYg/p+Fm8vHwPSICqU9HJ+dHF2Ty0M6WVwVlf6RJdJGsrp1s9cbxfc/74PdQUssIhUjhlBO2RFlQECbgNpw5UleRB9FLnEDp33qMgdr7nwXiYCTjd04QSkdU3mXJYrFfwIDAQAB"
        let decodedSPKI = Array(Data(base64Encoded: rsaSPKI)!)

        let parsed = try orFail { try ASN1.parse(decodedSPKI) }
        XCTAssertThrowsError(try ASN1.SubjectPublicKeyInfo(asn1Encoded: parsed)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidASN1Object)
        }
    }

    func testSPKIWithUnsupportedCurve() throws {
        // This is an EC SPKI object with an unsupported named curve.
        let b64SPKI = "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEzN09Sbb+mhMIlUbOdoIoND8lNcoQPd/yZDjQi1IDyDQEvVvz1yhi5J0FPLAlM3hE2o/a+rASUz2UP4fX5Cpnxw=="
        let decodedSPKI = Array(Data(base64Encoded: b64SPKI)!)

        let parsed = try orFail { try ASN1.parse(decodedSPKI) }
        XCTAssertThrowsError(try ASN1.SubjectPublicKeyInfo(asn1Encoded: parsed)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidASN1Object)
        }
    }

    func testSEC1PrivateKeyWithUnknownVersion() throws {
        // This is the beginning of a SEC1 private key with hypothetical version number 5. We should reject it
        let weirdSEC1: [UInt8] = [0x30, 0x03, 0x02, 0x01, 0x05]

        let parsed = try orFail { try ASN1.parse(weirdSEC1) }
        XCTAssertThrowsError(try ASN1.SEC1PrivateKey(asn1Encoded: parsed)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidASN1Object)
        }
    }

    func testSEC1PrivateKeyUnsupportedKeyType() throws {
        // This is an EC SPKI object with an unsupported named curve.
        let b64SEC1 = "MHQCAQEEINIuVmNF7g1wNCJWXDpgL+09jATtaS1n0SxqqQneHi+woAcGBSuBBAAKoUQDQgAEB7v/p7gvuV0aDx02EF6a+pr563p+FzRJXI+COWHdr+XRcjg6vEi4n3Jj7ksmEg4t1x6E1xFyTvF3eV/B/XVXbw=="
        let decodedSEC1 = Array(Data(base64Encoded: b64SEC1)!)

        let parsed = try orFail { try ASN1.parse(decodedSEC1) }
        XCTAssertThrowsError(try ASN1.SEC1PrivateKey(asn1Encoded: parsed)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidASN1Object)
        }
    }

    func testPKCS8KeyWithNonMatchingKeyOIDS() throws {
        // This is a stubbed PKCS8 key with mismatched OIDs in the inner and outer payload. We have to serialize it out, sadly.
        var serializer = ASN1.Serializer()
        try orFail {
            try serializer.appendConstructedNode(identifier: .sequence) { coder in
                try coder.serialize(0)
                try coder.serialize(ASN1.RFC5480AlgorithmIdentifier.ecdsaP256)

                var subCoder = ASN1.Serializer()
                try subCoder.serialize(ASN1.SEC1PrivateKey(privateKey: [], algorithm: .ecdsaP384, publicKey: []))  // We won't notice these are empty either, but we will notice the algo mismatch.
                let serializedKey = ASN1.ASN1OctetString(contentBytes: subCoder.serializedBytes[...])

                try coder.serialize(serializedKey)
            }
        }

        let parsed = try orFail { try ASN1.parse(serializer.serializedBytes) }
        XCTAssertThrowsError(try ASN1.PKCS8PrivateKey(asn1Encoded: parsed)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidASN1Object)
        }
    }

    func testSimplePEMP256SPKI() throws {
        let pemPublicKey = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb4nB0k8CBVnKCHVHkxuXAkSlZuO5
Nsev1rzcRv5QHiJuWUKomFGadQlMSGwoDOHEDdW3ujcA6t0ADteHw6KrZg==
-----END PUBLIC KEY-----
"""

        // Test the working public keys.
        let signingKey = try orFail { try P256.Signing.PublicKey(pemRepresentation: pemPublicKey) }
        let keyAgreementKey = try orFail { try P256.KeyAgreement.PublicKey(pemRepresentation: pemPublicKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)

        // Now the non-matching public keys.
        XCTAssertThrowsError(try P384.Signing.PublicKey(pemRepresentation: pemPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(pemRepresentation: pemPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
        XCTAssertThrowsError(try P521.Signing.PublicKey(pemRepresentation: pemPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(pemRepresentation: pemPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }

        // Now the private keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(pemRepresentation: pemPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(pemRepresentation: pemPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P384.Signing.PrivateKey(pemRepresentation: pemPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(pemRepresentation: pemPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P521.Signing.PrivateKey(pemRepresentation: pemPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(pemRepresentation: pemPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }

        // Validate we can reserialize.
        let firstReserialization = signingKey.pemRepresentation
        let secondReserialization = keyAgreementKey.pemRepresentation
        XCTAssertEqual(firstReserialization, pemPublicKey)
        XCTAssertEqual(secondReserialization, pemPublicKey)
    }

    func testSimplePEMP384SPKI() throws {
        let pemPublicKey = """
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEBwY0l7mq7hSBEZRld5ISWfSoFsYN3wwM
hdD3cMU95DmYXzbqVHB4dCfsy7bexm4h9c0zs4CyTPzy3DV3vfmv1akQJIQv7l08
lx/YXNeGXTN4Gr9r4rwA5GvRl1p6plPL
-----END PUBLIC KEY-----
"""

        // Test the working public keys.
        let signingKey = try orFail { try P384.Signing.PublicKey(pemRepresentation: pemPublicKey) }
        let keyAgreementKey = try orFail { try P384.KeyAgreement.PublicKey(pemRepresentation: pemPublicKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)

        // Now the non-matching public keys.
        XCTAssertThrowsError(try P256.Signing.PublicKey(pemRepresentation: pemPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(pemRepresentation: pemPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
        XCTAssertThrowsError(try P521.Signing.PublicKey(pemRepresentation: pemPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(pemRepresentation: pemPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }

        // Now the private keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(pemRepresentation: pemPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(pemRepresentation: pemPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P384.Signing.PrivateKey(pemRepresentation: pemPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(pemRepresentation: pemPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P521.Signing.PrivateKey(pemRepresentation: pemPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(pemRepresentation: pemPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }

        // Validate we can reserialize.
        let firstReserialization = signingKey.pemRepresentation
        let secondReserialization = keyAgreementKey.pemRepresentation
        XCTAssertEqual(firstReserialization, pemPublicKey)
        XCTAssertEqual(secondReserialization, pemPublicKey)
    }

    func testSimplePEMP521SPKI() throws {
        let pemPublicKey = """
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAp3v1UQWvSyQnkAUEBu+x/7ZrPtNJ
SCUk9kMvuZMyGP1idwvspALuJjzrSFFlXObjlOjxucSbWhTYF/o3nc0XzpAA3dxA
BYiMqH9vrVePoJMpv+DMdkUiUJ/WqHSOu9bJEi1h4fdqh5HHx4QZJY/iX/59VAi1
uSbAhALvbdGFbVpkcOs=
-----END PUBLIC KEY-----
"""

        // Test the working public keys.
        let signingKey = try orFail { try P521.Signing.PublicKey(pemRepresentation: pemPublicKey) }
        let keyAgreementKey = try orFail { try P521.KeyAgreement.PublicKey(pemRepresentation: pemPublicKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)

        // Now the non-matching public keys.
        XCTAssertThrowsError(try P256.Signing.PublicKey(pemRepresentation: pemPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(pemRepresentation: pemPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
        XCTAssertThrowsError(try P384.Signing.PublicKey(pemRepresentation: pemPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(pemRepresentation: pemPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }

        // Now the private keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(pemRepresentation: pemPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(pemRepresentation: pemPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P384.Signing.PrivateKey(pemRepresentation: pemPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(pemRepresentation: pemPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P521.Signing.PrivateKey(pemRepresentation: pemPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(pemRepresentation: pemPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }

        // Validate we can reserialize.
        let firstReserialization = signingKey.pemRepresentation
        let secondReserialization = keyAgreementKey.pemRepresentation
        XCTAssertEqual(firstReserialization, pemPublicKey)
        XCTAssertEqual(secondReserialization, pemPublicKey)
    }

    func testSimplePEMP256PKCS8() throws {
        let pemPrivateKey = """
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZjQLlzempZx7YF1F
+MK1HWZTNgLcC1MAufb/2/YZYk6hRANCAAQwgn0PfkIHiZ/K+3zA//CoDqU2PqDc
aA3U5R68jmlZQITvMyBlMJl9Mjh0biIe88dAfRKeUm9FVMD2ErJ/006V
-----END PRIVATE KEY-----
"""

        // Test the working private keys.
        let signingKey = try orFail { try P256.Signing.PrivateKey(pemRepresentation: pemPrivateKey) }
        let keyAgreementKey = try orFail { try P256.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)

        // Now the non-matching private keys.
        XCTAssertThrowsError(try P384.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P521.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))

        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P384.Signing.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P521.Signing.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }

        // Validate we can reserialize.
        let firstReserialization = signingKey.pemRepresentation
        let secondReserialization = keyAgreementKey.pemRepresentation
        XCTAssertEqual(firstReserialization, pemPrivateKey)
        XCTAssertEqual(secondReserialization, pemPrivateKey)
    }

    func testSimplePEMP384PKCS8() throws {
        let pemPrivateKey = """
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDB7ERKhMR+mvz1NQ+oL
i6ZJMACOcwbUetWcNnB4Mnx3j4XuhpkkHEW8E1+rXyjZ3UmhZANiAASYH+emlyXM
kBSFJl0BiopDVuIIR47M4pLl00YNnuu/Rp5VHeVAHrP67i2Q92u5fk34eOSwQvkO
VvktWsgtzAomIam4SHqE9bhvrHy6kW6QzxlERHTL+YkXEX8c6t8VOxk=
-----END PRIVATE KEY-----
"""

        // Test the working private keys.
        let signingKey = try orFail { try P384.Signing.PrivateKey(pemRepresentation: pemPrivateKey) }
        let keyAgreementKey = try orFail { try P384.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)

        // Now the non-matching private keys.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P521.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))

        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P384.Signing.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P521.Signing.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }

        // Validate we can reserialize.
        let firstReserialization = signingKey.pemRepresentation
        let secondReserialization = keyAgreementKey.pemRepresentation
        XCTAssertEqual(firstReserialization, pemPrivateKey)
        XCTAssertEqual(secondReserialization, pemPrivateKey)
    }

    func testSimplePEMP521PKCS8() throws {
        let pemPrivateKey = """
-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAmMp6YYRfT6uA+DFi
VB/V7FGAgjjuin1GcF8eujBZTcNB8jyzyXfG7Ak80jd3yhrHhAg7rOOZYV72Ekz5
o05NKM2hgYkDgYYABAEIOePr9DPc9lGHqSYrGHX0ICvZxy3DLTjPcl7jgAcUU9NT
1DBvJ7aAAmzTImz9mKOJk14f1fxc1BsWjsf1hU4QOwFu1l+dIDcNYFUxjzsGMc5e
LsSxRn35ts4qogmz3kmerOc0smI8NIFiK/EuinK5Bs8PfPMW3ZOCIpvXbqyksLk0
rg==
-----END PRIVATE KEY-----
"""

        // Test the working private keys.
        let signingKey = try orFail { try P521.Signing.PrivateKey(pemRepresentation: pemPrivateKey) }
        let keyAgreementKey = try orFail { try P521.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)

        // Now the non-matching private keys.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P384.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))

        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P384.Signing.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P521.Signing.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }

        // Validate we can reserialize.
        let firstReserialization = signingKey.pemRepresentation
        let secondReserialization = keyAgreementKey.pemRepresentation
        XCTAssertEqual(firstReserialization, pemPrivateKey)
        XCTAssertEqual(secondReserialization, pemPrivateKey)
    }

    func testSimplePEMP256SEC1PrivateKey() throws {
        let pemPrivateKey = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHwS3r7tdBfDPSOaT/x6A2qvXFFXlGmnaYkxzrj1CQUHoAoGCCqGSM49
AwEHoUQDQgAE79HvsMQC9IyhZ7yCCYKmgz9zewM4KziWoVMXKN+7Cd5Ds+jK8V5q
hD6YVbbo/v1udmM5DfhHJiUW3Ww5++suRg==
-----END EC PRIVATE KEY-----
"""

        // Test the working private keys.
        let signingKey = try orFail { try P256.Signing.PrivateKey(pemRepresentation: pemPrivateKey) }
        let keyAgreementKey = try orFail { try P256.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)

        // Now the non-matching private keys.
        XCTAssertThrowsError(try P384.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P521.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))

        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P384.Signing.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P521.Signing.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }

        // We can't reserialize the SEC1 keys, we don't emit them.
    }

    func testSimplePEMP384SEC1PrivateKey() throws {
        let pemPrivateKey = """
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDrN+qjvW7TqcXrKlTFbSP8AdbsIdqvRAgWHlaBicP7dkx+HKQidSiS
B2RLWyjSrs6gBwYFK4EEACKhZANiAAQrRiaztGpInYo1XqMnNokWY6g1TcgMuzgq
Ug6LzFQbCAqCrcnM9+c9Z4/63dC06ulL/KbLQgThjSiqRzgbzvmOvB0OzlpX1weK
usFrF4Pi0B9pKPmVCAlSzaxVEmRsbmw=
-----END EC PRIVATE KEY-----
"""

        // Test the working private keys.
        let signingKey = try orFail { try P384.Signing.PrivateKey(pemRepresentation: pemPrivateKey) }
        let keyAgreementKey = try orFail { try P384.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)

        // Now the non-matching private keys.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P521.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))

        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P384.Signing.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P521.Signing.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }

        // We can't reserialize the SEC1 keys, we don't emit them.
    }

    func testSimplePEMP521SEC1PrivateKey() throws {
        let pemPrivateKey = """
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBf4tGkyicrFEadZv7iWnmCGsDk7S18CTCUD7n4+XOG6GbVNLwpBsE
naUP5eXHm5Bxuiir0BIsKATXx0ZwEjULpfCgBwYFK4EEACOhgYkDgYYABAEiHfCR
mQtxxjthsfQ987aSYGgxcCLxBaj8/fW4U7jufPcqxz27x9wi1qB2rZmOKaSsh1JZ
wF5yOAMX4/acIK1OdgGzbafukRZjqF3wKVP8UFH0DzdNaZ8aSplgUu8gV2TjJyQB
1sCKaVuecBtTRiIwvnapv5PgQIgstPQmRhqVOLriDA==
-----END EC PRIVATE KEY-----
"""

        // Test the working private keys.
        let signingKey = try orFail { try P521.Signing.PrivateKey(pemRepresentation: pemPrivateKey) }
        let keyAgreementKey = try orFail { try P521.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)

        // Now the non-matching private keys.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P384.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))

        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P384.Signing.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P521.Signing.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
        }

        // We can't reserialize the SEC1 keys, we don't emit them.
    }

    func testSimpleDERP256SPKI() throws {
        let b64PublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIq+Qd2HviOb1JAkvKInCCec/gbZRnEZ6H9gO29wJ1H/a8Mmmog7b8nj+xEgo7Rh5dKlNgRaKvVjlLDllq+bPAA=="
        let derPublicKey = Data(base64Encoded: b64PublicKey)!

        // Test the working public keys.
        let signingKey = try orFail { try P256.Signing.PublicKey(derRepresentation: derPublicKey) }
        let keyAgreementKey = try orFail { try P256.KeyAgreement.PublicKey(derRepresentation: derPublicKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)

        // Now the non-matching public keys.
        XCTAssertThrowsError(try P384.Signing.PublicKey(derRepresentation: derPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(derRepresentation: derPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
        XCTAssertThrowsError(try P521.Signing.PublicKey(derRepresentation: derPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(derRepresentation: derPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }

        // Now the private keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(derRepresentation: derPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(derRepresentation: derPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P384.Signing.PrivateKey(derRepresentation: derPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(derRepresentation: derPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P521.Signing.PrivateKey(derRepresentation: derPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(derRepresentation: derPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }

        // Validate we can reserialize.
        let firstReserialization = signingKey.derRepresentation
        let secondReserialization = keyAgreementKey.derRepresentation
        XCTAssertEqual(firstReserialization, derPublicKey)
        XCTAssertEqual(secondReserialization, derPublicKey)
    }

    func testSimpleDERP384SPKI() throws {
        let b64PublicKey = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEvt9xABn4WAo0EQsp3BMEd26f3qrXJ5RrhU1i2wp0G29oK2cdNareBirnyjlsQEg/OQ+ZQyKmMrxm5OrbhvJf/+97dc6phzb2R/blH62I65BiUSBAsGaXU69ObTPOwDKT"
        let derPublicKey = Data(base64Encoded: b64PublicKey)!

        // Test the working public keys.
        let signingKey = try orFail { try P384.Signing.PublicKey(derRepresentation: derPublicKey) }
        let keyAgreementKey = try orFail { try P384.KeyAgreement.PublicKey(derRepresentation: derPublicKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)

        // Now the non-matching public keys.
        XCTAssertThrowsError(try P256.Signing.PublicKey(derRepresentation: derPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(derRepresentation: derPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
        XCTAssertThrowsError(try P521.Signing.PublicKey(derRepresentation: derPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(derRepresentation: derPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }

        // Now the private keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(derRepresentation: derPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(derRepresentation: derPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P384.Signing.PrivateKey(derRepresentation: derPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(derRepresentation: derPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P521.Signing.PrivateKey(derRepresentation: derPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(derRepresentation: derPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }

        // Validate we can reserialize.
        let firstReserialization = signingKey.derRepresentation
        let secondReserialization = keyAgreementKey.derRepresentation
        XCTAssertEqual(firstReserialization, derPublicKey)
        XCTAssertEqual(secondReserialization, derPublicKey)
    }

    func testSimpleDERP521SPKI() throws {
        let b64PublicKey = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAfH9fsVM7MdTe88+kvkZmFq9nPLMAPvCyAf5PYnJ7qV3W0rtVC2R3c0Aw21QxeN4XAIFcElO9NQ+ErT/m4o6+1YgBlLfBTnHKTq/WTNjQWxQk8i1PzHMsplT41OMAm0LaHwi9s+mWUIGlbfcP+MmVKY5dMkskPsU2YBlLZI81xk+z2X4="
        let derPublicKey = Data(base64Encoded: b64PublicKey)!

        // Test the working public keys.
        let signingKey = try orFail { try P521.Signing.PublicKey(derRepresentation: derPublicKey) }
        let keyAgreementKey = try orFail { try P521.KeyAgreement.PublicKey(derRepresentation: derPublicKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)

        // Now the non-matching public keys.
        XCTAssertThrowsError(try P256.Signing.PublicKey(derRepresentation: derPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(derRepresentation: derPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
        XCTAssertThrowsError(try P384.Signing.PublicKey(derRepresentation: derPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(derRepresentation: derPublicKey)) { error in
            guard case .incorrectParameterSize = error as? CryptoKitError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }

        // Now the private keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(derRepresentation: derPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(derRepresentation: derPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P384.Signing.PrivateKey(derRepresentation: derPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(derRepresentation: derPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P521.Signing.PrivateKey(derRepresentation: derPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(derRepresentation: derPublicKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }

        // Validate we can reserialize.
        let firstReserialization = signingKey.derRepresentation
        let secondReserialization = keyAgreementKey.derRepresentation
        XCTAssertEqual(firstReserialization, derPublicKey)
        XCTAssertEqual(secondReserialization, derPublicKey)
    }

    func testSimpleDERP256PKCS8() throws {
        let b64PrivateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgxWaWfbbhHsTjtEwkANo6ZDeJ2CARYhjOSt2auAW7xNOhRANCAAQsAL3hTMCCbh1kVCSJa8V22WLNDriEpVOLEJXiVFEwAFjWd1BufewuT69tYa0hyB1Q3pt12HPK2c1KGwjOpScW"
        let derPrivateKey = Data(base64Encoded: b64PrivateKey)!

        // Test the working private keys.
        let signingKey = try orFail { try P256.Signing.PrivateKey(derRepresentation: derPrivateKey) }
        let keyAgreementKey = try orFail { try P256.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)

        // Now the non-matching private keys.
        XCTAssertThrowsError(try P384.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P521.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))

        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P384.Signing.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P521.Signing.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }

        // Validate we can reserialize.
        let firstReserialization = signingKey.derRepresentation
        let secondReserialization = keyAgreementKey.derRepresentation
        XCTAssertEqual(firstReserialization, derPrivateKey)
        XCTAssertEqual(secondReserialization, derPrivateKey)
    }

    func testSimpleDERP384PKCS8() throws {
        let b64PrivateKey = "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAsdACCJGneotN0y5zQjZxImZuH3TuvHeKWXKi2m6d3fYsGOufibIqaxfCLVZGvxb2hZANiAARL6IhECKbw5UCSqGaaZ3H5FNbXuk/4y4QTJLhdQRBkibr6YjEzFGDgd1yjU0msBOMBvx3oCZ5rPgVaogQXPdZbx8PnTt2I+2x2BuoRibA+/yCAyJSluVm/005p0EcAmuI="
        let derPrivateKey = Data(base64Encoded: b64PrivateKey)!

        // Test the working private keys.
        let signingKey = try orFail { try P384.Signing.PrivateKey(derRepresentation: derPrivateKey) }
        let keyAgreementKey = try orFail { try P384.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)

        // Now the non-matching private keys.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P521.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))

        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P384.Signing.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P521.Signing.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }

        // Validate we can reserialize.
        let firstReserialization = signingKey.derRepresentation
        let secondReserialization = keyAgreementKey.derRepresentation
        XCTAssertEqual(firstReserialization, derPrivateKey)
        XCTAssertEqual(secondReserialization, derPrivateKey)
    }

    func testSimpleDERP521PKCS8() throws {
        let b64PrivateKey = "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIA2u5+KHPk/vVrYI53Khh3WrFmxUCQ5YeK6HAi+GyebeRM3w1KoQuD4oHocp2aKffjjWKVkEfLRfjraJgh1jH+GPihgYkDgYYABAC4M0cSEZ+hKwn65PQtdFu+L1ZdBt4kjrGJ2ggNG+tQ3z4S11KV9b+R+CyUajajhU2nJ4UkHQO5bEaTPmaWySFSVQEZilLlYtnQZSKGLS2DR4zBsny0O2+D5DpFSYKsDPN23MdOBdTam2Gqtm/WAirVmXMqs8v5VSjmh3i/EG6EDPEtXw=="
        let derPrivateKey = Data(base64Encoded: b64PrivateKey)!

        // Test the working private keys.
        let signingKey = try orFail { try P521.Signing.PrivateKey(derRepresentation: derPrivateKey) }
        let keyAgreementKey = try orFail { try P521.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)

        // Now the non-matching private keys.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P384.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))

        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P384.Signing.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P521.Signing.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }

        // Validate we can reserialize.
        let firstReserialization = signingKey.derRepresentation
        let secondReserialization = keyAgreementKey.derRepresentation
        XCTAssertEqual(firstReserialization, derPrivateKey)
        XCTAssertEqual(secondReserialization, derPrivateKey)
    }

    func testSimpleDERP256SEC1PrivateKey() throws {
        let b64PrivateKey = "MHcCAQEEIKzmkxtADyr8LymuVMqpLFVlx27bdgT0+un4I2a3DE1KoAoGCCqGSM49AwEHoUQDQgAEZp2q8QP4shIBZIHS1b1ZBUeLbrpnTA6CB17iFzF8udyYmcRkDAPSBamFXf4IthinYkfnru/PymZl+tpeM56BOw=="
        let derPrivateKey = Data(base64Encoded: b64PrivateKey)!

        // Test the working private keys.
        let signingKey = try orFail { try P256.Signing.PrivateKey(derRepresentation: derPrivateKey) }
        let keyAgreementKey = try orFail { try P256.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)

        // Now the non-matching private keys.
        XCTAssertThrowsError(try P384.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P521.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))

        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P384.Signing.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P521.Signing.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }

        // We can't reserialize the SEC1 keys, we don't emit them.
    }

    func testSimpleDERP384SEC1PrivateKey() throws {
        let b64PrivateKey = "MIGkAgEBBDAF5FSBF7Se55zRtIyMRcKgFWAEx0ixHqeevUFerPVtvZC7U2LfGOx9GMR5V+Nj7uagBwYFK4EEACKhZANiAAQCXRQ9B+RYv6zvQVdP2xZ0/8U3nzcOdWuAMb0BvjqkE/xDhHp7DYNGEv4pWhj1hkl9Tv5jum0eqAGgzq1hLpeY2aWnwk8fqnrDVDcnWrZe/9QpmHGaOP1YJXuyaJRnBWo="
        let derPrivateKey = Data(base64Encoded: b64PrivateKey)!

        // Test the working private keys.
        let signingKey = try orFail { try P384.Signing.PrivateKey(derRepresentation: derPrivateKey) }
        let keyAgreementKey = try orFail { try P384.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)

        // Now the non-matching private keys.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P521.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))

        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P384.Signing.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P521.Signing.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }

        // We can't reserialize the SEC1 keys, we don't emit them.
    }

    func testSimpleDERP521SEC1PrivateKey() throws {
        let b64PrivateKey = "MIHcAgEBBEIBFQwJ2Spw90Sn7oOnBKU6ob5Zoq9qBo6YiarvTok4jurO2VSQTyrmk02KK8EmZ/ZQqXRl/mZm0hLXwKBdUe+MPfSgBwYFK4EEACOhgYkDgYYABAEFYqZABFf2NBxxLb7rUV/pKAO8IF/ddIs2BY9dU/Ru6sQBOT6lzr5pGZC4a0o30ZGWNOvMq503Ev7/XDjW8fdPCQBGm4JGOOI/Pr008wsASEQOvloAUEQ+HOTZ94Dk3OTHqqahtgjp2BLGvMWHf1PwMsXv98nLE+LEYTQ8fzTgbUJwxg=="
        let derPrivateKey = Data(base64Encoded: b64PrivateKey)!

        // Test the working private keys.
        let signingKey = try orFail { try P521.Signing.PrivateKey(derRepresentation: derPrivateKey) }
        let keyAgreementKey = try orFail { try P521.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey) }
        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)

        // Now the non-matching private keys.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P384.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P384.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))

        // Now the public keys, which all fail.
        XCTAssertThrowsError(try P256.Signing.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P384.Signing.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P521.Signing.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }
        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(derRepresentation: derPrivateKey)) { error in
            XCTAssertEqual(error as? CryptoKitASN1Error, .unexpectedFieldType)
        }

        // We can't reserialize the SEC1 keys, we don't emit them.
    }

    func testInvalidPEMP521PKCS8() throws {
        // This key is generated by an older OpenSSL or LibreSSL, which forgets to zero-pad the
        // private key. We want to validate that we correctly reject this.
        let pemPrivateKey = """
-----BEGIN PRIVATE KEY-----
MIHtAgEAMBAGByqGSM49AgEGBSuBBAAjBIHVMIHSAgEBBEFtmqAvS3jccVAam+Yn
y3iiwMi6q8roJeAtxqdOkZUCdZ3Rf6lD0nehiH4QN7xOrhHrAIeZWe0ld2XUawGF
H0ltO6GBiQOBhgAEAJHKKLTdXvL1DyZX4TI0kEi63I9cwtg09CQZ/Bp+K9MWsx9S
bjIEBcr3yEKlUmRW+TKNoXo50ycbl4DlLknN2VbGAXE22e2sz8RQ1omvDE6lLBvB
A5UvlNrk6ioTg2tumXD3Co06r1Hn+7lkkcjfT5mZO4jy7vP9ItvprJrIa6ySzVQ8
-----END PRIVATE KEY-----
"""

        // This is not a valid private key for P521.
        XCTAssertThrowsError(try P521.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))
    }

    func testInvalidDERP521PKCS8() throws {
        // This key is generated by an older OpenSSL or LibreSSL, which forgets to zero-pad the
        // private key. We want to validate that we correctly reject this.
        let b64PrivateKey = "MIHtAgEAMBAGByqGSM49AgEGBSuBBAAjBIHVMIHSAgEBBEG1erZ/O4JMc11uT3SLJPQ4ICWbEdM0e8d1mI/uUhbZ6nE90jq38FZYkvKf6q3d1DUWJj8aWjktq2+gfCSD+XFulaGBiQOBhgAEAYKbRHQpjqaS17SwXAQzpUct9i+TyVUdDtQVpwxVTVhuklvTEWqypvSAyhqo9nPf/aKHl4fQD94Fd3RTzOmW8x+nAGnWGO6ZG1OQ72NCmT9fyB8dG2ifeDpICKuEq6reVIBDSQvi5F98C/lEIgu2r+MGYWj+S7pjEmSqksSjsJ3Oxo9U"
        let derPrivateKey = Data(base64Encoded: b64PrivateKey)!

        // This is not a valid private key for P521.
        XCTAssertThrowsError(try P521.Signing.PrivateKey(derRepresentation: derPrivateKey))
        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(derRepresentation: derPrivateKey))
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
        struct BigIntOfBytes: ASN1IntegerRepresentable {
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
    }
}

#endif
