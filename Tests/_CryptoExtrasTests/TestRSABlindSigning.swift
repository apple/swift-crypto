//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
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
import Crypto
@testable import _CryptoExtras

fileprivate struct TestVector: Codable {
    var name, p, q, n, e, d, msg, msg_prefix, prepared_msg, salt, inv, blinded_msg, blind_sig, sig: String

    var parameters: _RSA.BlindSigning.Parameters<SHA384> {
        let messagePaddingByteCount = (self.prepared_msg.count - self.msg.count) / 2
        let saltByteCount = self.salt.count / 2
        switch (saltByteCount, messagePaddingByteCount) {
        case (0, 0):
            return .RSABSSA_SHA384_PSSZERO_Deterministic
        case (0, 32):
            return .RSABSSA_SHA384_PSSZERO_Randomized
        case (SHA384.byteCount, 0):
            return .RSABSSA_SHA384_PSS_Deterministic
        case (SHA384.byteCount, 32):
            return .RSABSSA_SHA384_PSS_Randomized
        default:
            fatalError("Unsupported test vector; salt length: \(saltByteCount); message padding: \(messagePaddingByteCount).")
        }
    }

    static func load(from fileURL: URL) throws -> [Self] {
        let json = try Data(contentsOf: fileURL)
        let decoder = JSONDecoder()
        return try decoder.decode([Self].self, from: json)
    }
}

final class TestRSABlindSigning: XCTestCase {
    func testAgainstRFC9474TestVectors() throws {
        let testVectors = try TestVector.load(from: URL(
            fileURLWithPath: "../_CryptoExtrasVectors/rfc9474.json",
            relativeTo: URL(fileURLWithPath: #file)
        ))

        // Security framework doesn't have the API we need to support the PSSZERO variants.
        #if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        let filteredTestVectors = testVectors.filter { $0.parameters.padding.backing != .pssZero }
        #else
        let filteredTestVectors = testVectors
        #endif

        for testVector in filteredTestVectors {
            // Prepare
            do {
                let message = try Data(hexString: testVector.msg)
                switch testVector.parameters.preparation {
                case .identity:
                    let preparedMessage = _RSA.BlindSigning.prepare(message, parameters: testVector.parameters)
                    XCTAssertEqual(preparedMessage.rawRepresentation, message)
                case .randomized:
                    break  // Until we have SPI secure bytes.
                    let preparedMessage = _RSA.BlindSigning.prepare(message, parameters: testVector.parameters)
                    XCTAssertEqual(preparedMessage.rawRepresentation.dropFirst(32), message)
                }
            }

            // Blind
            do {
            }

            // BlindSign
            do {
                let privateKey = try _RSA.BlindSigning.PrivateKey(
                    nHexString: testVector.n,
                    eHexString: testVector.e,
                    dHexString: testVector.d,
                    pHexString: testVector.p,
                    qHexString: testVector.q,
                    parameters: testVector.parameters
                )
                let blindedMessage = try _RSA.BlindSigning.BlindedMessage(rawRepresentation: Data(hexString: testVector.blinded_msg))
                let blindSignature = try privateKey.blindSignature(for: blindedMessage)
                XCTAssertEqual(
                    blindSignature.rawRepresentation.hexString,
                    try Data(hexString: testVector.blind_sig).hexString
                )
            }

            // Finalize
            do {
            }

            // Verification
            do {
                let publicKey = try _RSA.BlindSigning.PublicKey(nHexString: testVector.n, eHexString: testVector.e, parameters: testVector.parameters)
                let signature = try _RSA.Signing.RSASignature(rawRepresentation: Data(hexString: testVector.sig))
                let preparedMessage = try _RSA.BlindSigning.PreparedMessage(rawRepresentation: Data(hexString: testVector.prepared_msg))
                XCTAssert(publicKey.isValidSignature(signature, for: preparedMessage.rawRepresentation))
            }
        }
    }

    func testBlindSign_keyParameterCombinations() throws {
        let keySizes: [_RSA.Signing.KeySize] = [
            .bits2048,
            .bits3072,
        ]
        let parameters: [_RSA.BlindSigning.Parameters] = [
            .RSABSSA_SHA384_PSSZERO_Deterministic,
            .RSABSSA_SHA384_PSSZERO_Randomized,
            .RSABSSA_SHA384_PSS_Deterministic,
            .RSABSSA_SHA384_PSS_Randomized,
        ]

        for keySize in keySizes {
            for parameters in parameters {
                let privateKey = try _RSA.BlindSigning.PrivateKey(keySize: keySize, parameters: parameters)

                // Fake a blinded message with appropriate size for the key modulus.
                let signingKey = try _RSA.Signing.PrivateKey(pemRepresentation: privateKey.pemRepresentation)
                let blindedMessageProxyBytes = try signingKey.signature(for: SHA384.hash(data: Data("plaintext".utf8)), padding: .PSSZERO).rawRepresentation
                let blindedMessageProxy = _RSA.BlindSigning.BlindedMessage(rawRepresentation: blindedMessageProxyBytes)

                _ = try privateKey.blindSignature(for: blindedMessageProxy)
            }
        }
    }

    func testBlindSign_messageTooLargeForKeyModulus_throwsIncorrectParameterSize() throws {
        let privateKeyPEM = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEogIBAAKCAQEAnuCNx4shvbE2puRC0DiTGVnQHN3BaUm2g6Db1DqoFndFUcxP
        ZpxkMsr+zq5rB/sJlfpYvK3INZYKNSXeCtt3sJYmABWutI/MIuPsHZVdG98Cp3Mr
        7Zt+XOIE6zr9nK7yDN1KpQHNUE4iRfaAMRFy2r4r+va8M8KYbw3fTZmnk0SFjS0l
        4x3JmFbmjqTKWGEXARmAX6niA/c7Ruhq+hvnG9zkOnPzr6z3R6Eo0whXYoC+Ue3f
        maHmB7IfpkDLBPy9xdCvX6Hx6Q/sDC9nAOBdfo4c0Zy7gb61Lv5CAT0DPC8KA7VG
        0QJY+ozqsrvrXMV5FNnAP+TtqSE0ENaESY3bvwIDAQABAoIBABd2Nbm39B2dI+L1
        ZmB1WlOuDauVm9A+kHNTt+LZXqUiq9vuffM7ORi/HW3MGAYvrjS1qZEDYMN5Crza
        gLW9vykWoznz+b60VYL5gY7E1eEdx7iOq3gFNF3nCq7qITWYKCp6K2G+qGEpiKoo
        Qrn8R6fB2aDP+u7x16zesZE2FacLhc/N4uzkJsus6on+y0QfM5w5qlhFISeWq+lp
        FimZSw6BdvbpK+iSm5zY03NYLSPdllmTJ+FV+Yc5YXdaqrz9p+v0EEnkUwQm3Sm+
        shEgzXeeZQgE/g9zcWuaAnz5hkcGUzb43QBbbh0E4tGFdSOF3D+z090Pe6eMwAyp
        ldlBR7ECgYEAzvFvMDzfaOtTVemMy+hgRm/N1WrEYBl1XxHiTgkjaNEjw9YiiorL
        klAK5nurE1RqwclqE+HtPKr44nZLYFw2Vlqpfj1tk/Ln4TPQukZrZvfQNJFZYjym
        ATgw3i1bwVfJ5rdqY8wBjfBVjrCacO8eoZ1lB2fqb9xgW59/+w/cdnUCgYEAxIov
        oT9sdwF0nTY5xA+MOPYYjEY5HDdu/KKB+K8sUkgQbmoiQIVc3cKec4l5SrhB1ncE
        UBGyyX7tmF+fBdWS550zP12m4Qs3Fce1foxa3aaKXK4/sj3qLYI31FPM2z6vdgE4
        bJbYu5SITlkz3wZbkOeph/2BHKRFfDHPg0cnSuMCgYBylour2TkX/p5RhxYYXp7Y
        wdXm48zDLbWpI9z8uuCpjIzSRsMvlbUtWjb+8uGCvY6zqVScl9BmdIGF3FzWiZjo
        7iDGLzt63dj6AVgFnTKhfH0Ebqtg0xZUvImKrPEOuQ6qO0uk4PTHZJnrfey2tiFu
        +hlUJX1R3WRZt5MFMP4xdQKBgEwHSLWP212N6paGS4JUoWHHkWdyItWPfBeupaiV
        2wdZaUHNPMLI1EvU5Ya8P3dwH8fe8oQm1Iqt1yuCkfmnzNRcM17n045q0DxUrRjv
        IpdrvUps/abt3JEONpqkcDK/5RA5GKKpF944byIfz7kOtI0xkJtSrYdu5JJOkn+u
        Hr0RAoGAGSlR9rAEbWRaNx2PJWmyb/A5LVWU85SKCnBl13v4OqDZJ+3akvYxn8WK
        cWbG8agtNNiqR4Rt+ehSZGwRwT6ZXL5BSj0UHJTZk1GrzMz4+rAo238UnDbgEExn
        UeXjD0eUYZEtiLapKsXqTtaxmUfPT8vQ9v1GKJfTgTLX+HVdRGg=
        -----END RSA PRIVATE KEY-----
        """
        let blindedMessageHexString = """
        e949d41ab280c8b179345477ae32d17364e18961303b75669d426f435abecb91\
        aab63487311197cb7c204b87408a5e39b04e04e1b3dcab49d691dbcdf578ed04\
        dc7362f1b56b2d39f43708dcb33fabc569bc21fd5c1156e042c366b39771e391\
        12082231f9abdcb3ebd3b98d25f66b42147774aad1c4f1d59d11e519dd1a1925\
        37af580dcc28431902044d86815db8d8643df4beb337255cb4563e4c1d84c011\
        30170f645956be2e1945396327c666ddb10772645c2ae4de8c9c4912c9f7c14d\
        d42b43aa98cef406d45c1df3035e115e2a878766624c9d31488518e2667987fd\
        2950c126425538ad676e23a26c0f3e0523a307c557e3a6471771a5635b704c56
        """
        let privateKey = try _RSA.BlindSigning.PrivateKey(pemRepresentation: privateKeyPEM)
        let blindedMessage = try _RSA.BlindSigning.BlindedMessage(rawRepresentation: Data(hexString: blindedMessageHexString))
        XCTAssertThrowsError(try privateKey.blindSignature(for: blindedMessage)) { error in
            guard let error = error as? CryptoKitError, case .incorrectParameterSize = error else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
    }

    func testEndToEndAPIUsage() throws {
        try XCTSkipIf(true, "Until the client operations are implemented, this is just here to check the types compose")

        // 1. [Issuer] Create private key (other initializers are available).
        let privateKeyPEM = "This will not work, just here to test the API."
        let privateKey = try _RSA.BlindSigning.PrivateKey(pemRepresentation: privateKeyPEM, parameters: .RSABSSA_SHA384_PSS_Randomized)

        // 2. [Client] Create public key (other initializers are available).
        let publicKeyPEM = "This will not work, just here to test the API."
        let publicKey = try _RSA.BlindSigning.PublicKey(pemRepresentation: publicKeyPEM, parameters: .RSABSSA_SHA384_PSS_Randomized)

        // 3. [Client] Have a message they wish to use.
        let message = Data("This is some input data".utf8)

        // 4. [Client] Prepare the message.
        let preparedMessage = _RSA.BlindSigning.prepare(message, parameters: .RSABSSA_SHA384_PSS_Randomized)

        // 5. [Client] Blind the message.
        let (blindedMessage, blindInverse) = try publicKey.blind(preparedMessage)

        // 6. [Issuer] Blind sign.
        let blindSignature = try privateKey.blindSignature(for: blindedMessage)

        // 7. [Client] Finalize.
        let unblindedSignature = try publicKey.finalize(blindSignature, for: preparedMessage, blindInverse: blindInverse)

        // 8. [Verifier] Verify.
        _ = publicKey.isValidSignature(unblindedSignature, for: preparedMessage.rawRepresentation)
    }
}
