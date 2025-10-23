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

import CryptoExtras
import XCTest

final class Curve25519PEMTests: XCTestCase {
    func testSigningPrivateKeyPEMRoundTrip() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let imported = try Curve25519.Signing.PrivateKey(pemRepresentation: privateKey.pemRepresentation)
        XCTAssertEqual(imported.rawRepresentation, privateKey.rawRepresentation)
    }

    func testSigningPublicKeyPEMRoundTrip() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let imported = try Curve25519.Signing.PublicKey(pemRepresentation: publicKey.pemRepresentation)
        XCTAssertEqual(imported.rawRepresentation, publicKey.rawRepresentation)
    }

    func testKeyAgreementPrivateKeyPEMRoundTrip() throws {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let imported = try Curve25519.KeyAgreement.PrivateKey(pemRepresentation: privateKey.pemRepresentation)
        XCTAssertEqual(imported.rawRepresentation, privateKey.rawRepresentation)
    }

    func testKeyAgreementPublicKeyPEMRoundTrip() throws {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        let imported = try Curve25519.KeyAgreement.PublicKey(pemRepresentation: publicKey.pemRepresentation)
        XCTAssertEqual(imported.rawRepresentation, publicKey.rawRepresentation)
    }

    func testImportOpenSSLSigningPrivateKeyPEM() throws {
        // Generated via `openssl genpkey -algorithm Ed25519 -outform PEM`
        let pem = """
            -----BEGIN PRIVATE KEY-----
            MC4CAQAwBQYDK2VwBCIEIIHEchKSA2A/z1r4tVHJ9f+yS6YXhUbBdHJiryZnRqnD
            -----END PRIVATE KEY-----
            """
        let key = try Curve25519.Signing.PrivateKey(pemRepresentation: pem)
        XCTAssertEqual(key.rawRepresentation.count, 32)
    }

    func testImportOpenSSLKeyAgreementPrivateKeyPEM() throws {
        // Generated via `openssl genpkey -algorithm X25519 -outform PEM`
        let pem = """
            -----BEGIN PRIVATE KEY-----
            MC4CAQAwBQYDK2VuBCIEIMDJoDr+3A91QpL8BLIeCKSAKI5T7frtzEaE5HzugtR1
            -----END PRIVATE KEY-----
            """
        let key = try Curve25519.KeyAgreement.PrivateKey(pemRepresentation: pem)
        XCTAssertEqual(key.rawRepresentation.count, 32)
    }

    func testInvalidPEMThrows() {
        let invalidPEM = """
            -----BEGIN PRIVATE KEY-----
            abc
            -----END PRIVATE KEY-----
            """
        XCTAssertThrowsError(try Curve25519.Signing.PrivateKey(pemRepresentation: invalidPEM))
        XCTAssertThrowsError(try Curve25519.KeyAgreement.PrivateKey(pemRepresentation: invalidPEM))

        let invalidPublicPEM = """
            -----BEGIN PUBLIC KEY-----
            xyz
            -----END PUBLIC KEY-----
            """
        XCTAssertThrowsError(try Curve25519.Signing.PublicKey(pemRepresentation: invalidPublicPEM))
        XCTAssertThrowsError(try Curve25519.KeyAgreement.PublicKey(pemRepresentation: invalidPEM))
    }

    func testWrongAlgorithmOIDThrows() throws {
        XCTAssertThrowsError(try Curve25519.Signing.PrivateKey(pemRepresentation: rsaPEM))
        XCTAssertThrowsError(try Curve25519.KeyAgreement.PublicKey(pemRepresentation: rsaPEM))
    }

    func testSigningPrivatePublicKeyConsistency() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey

        let importedPrivate = try Curve25519.Signing.PrivateKey(pemRepresentation: privateKey.pemRepresentation)
        let importedPublic = try Curve25519.Signing.PublicKey(pemRepresentation: publicKey.pemRepresentation)

        XCTAssertEqual(importedPrivate.publicKey.rawRepresentation, importedPublic.rawRepresentation)
    }

    func testKeyAgreementPrivatePublicKeyConsistency() throws {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey

        let importedPrivate = try Curve25519.KeyAgreement.PrivateKey(pemRepresentation: privateKey.pemRepresentation)
        let importedPublic = try Curve25519.KeyAgreement.PublicKey(pemRepresentation: publicKey.pemRepresentation)

        XCTAssertEqual(importedPrivate.publicKey.rawRepresentation, importedPublic.rawRepresentation)
    }

    let rsaPEM = """
        -----BEGIN PRIVATE KEY-----
        MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDL8W1D9w5zHpmD
        JqpTngIRJ+Sm21e42cRnTudhdejzKUiJQWkHSvQV5yC/+0iEXUsUJYEdSyrKhJFD
        PT+IFGdjIiwb7IX+rUreWXlD/YYBL3/byMG4kYoO4oiPp2A+WvfeyLpuN549OXhk
        7o5kXEZjKfjHTfmnAbCMoYW5BEpiHQC3HAeJZ5EiwAn8HZn5UY6lxJcf7H9hR83x
        D0W7IZTNyxUu4aLNuihFIxJKgP/L/y95Y6ddZsyyHQopM43/7JOYBwufa07MWaxi
        AdBdq1bR/ZeOt2aZaXhV+J6QUoUO8Z6fG6b2cQmvMgk4ybqoeciLII0DfFsyqavu
        ip4hRr59AgMBAAECggEAUIw994XwMw922hG/W98gOd5jtHMVJnD73UGQqTGEm+VG
        PM+Ux8iWtr/ec3Svo3elW4OkhwlVET9ikAf0u64zVzf769ty4K9YzpDQEEZlUrqL
        6SZVPKxetppKDVKx9G7BT0BAQZ+947h7EIIXwxOeyTOeijkFzSwhqqlwwy4qoqzV
        FTQS20QHE62hxzwuS5HBqw8ds183qAg9NbzR0Cp4za9qTiBB6C8KEcLqeatO+q+d
        VCDsJcAMZOvW14N6BozKgbQ/WXZQ/3kNUPBndZLzzqaILFNmB1Zf2DVVJ9gU7+EK
        xOac60StIfG81NllCTBrmRVq8yitNqwmutHMlxrIkQKBgQDvp39MkEHtNunFGkI5
        R8IB5BZjtx5OdRBKkmPasmNU8U0XoQAJUKY/9piIpCtRi87tMXv8WWmlbULi66pu
        4BnMIisw78xlIWRZTSizFrkFcEoVgEnbZBtSrOg/J5PAcjLEGCQoAdmMXAekR2/m
        htv7FPijHPNUjyIFLaxwjl9izwKBgQDZ2mQeKNRHjIb5ZBzB0ZCvUy2y4+kaLrhZ
        +CWMN1flL4dd1KuZKvCEfHY9kWOjqw6XneN4yT0aPmbBft4fihiiNW0Sm8i+fSpy
        g0klw2HJl49wnwctBpRgTdMKGo9n14OGeu0xKOAy7I4j1tKrUXiRWnP9R583Ti7c
        w7YHgdHM8wKBgEV147SaPzF08A6bzMPzY2zO4hpmsdcFoQIsKdryR04QXkrR9EO+
        52C0pYM9Kf0Jq6Ed7ZS3iaJT58YDjjNyqqd648/cQP6yzfYAIiK+HERSRnay5zU6
        b5zn1qyvWOi3cLVbVedumdJPvjtEJU/ImKvOaT5FntVMYwzjLw60hTsLAoGAZJnt
        UeAY51GFovUQMpDL96q5l7qXknewuhtVe4KzHCrun+3tsDWcDBJNp/DTymjbvDg1
        KzoC9XOLkB8+A+KJrZ5uWAGImi7Cw07NIJsxNR7AJonJjolTS4Wkxy2su49SNW/e
        yKzPm7SRjwtNDb/5pWXX2kaQx8Fa8qeOD7lrYPECgYAwQ6o0vYmr+L1tOZZgMVv9
        Jusa8beVUH5hyduJjmxbYOtFTkggAozdx7rs4BgyRsmDlV48cEmcVf/7IH4gMJLb
        O+bbERwCYUChe+piANhnwfwDHzbRd8mmQus54P06X7bWu6Rmi7gbQGVN/Z6VhbIm
        D2cOo0w4bk/3yb01xz1MEw==
        -----END PRIVATE KEY-----
        """
}
