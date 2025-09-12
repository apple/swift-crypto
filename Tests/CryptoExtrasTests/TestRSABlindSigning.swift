//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import XCTest
import Crypto
@testable import CryptoExtras

struct RFC9474TestVector: Codable {
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

    static let allValues: [Self] = try! RFC9474TestVector.load(from: URL(
        fileURLWithPath: "../CryptoExtrasVectors/rfc9474.json",
        relativeTo: URL(fileURLWithPath: #filePath)
    ))
}

final class TestRSABlindSigning: XCTestCase {
    func testAgainstRFC9474TestVectors() throws {
        for testVector in RFC9474TestVector.allValues {
            // Load key pair
            let privateKey = try _RSA.BlindSigning.PrivateKey(
                n: Data(hexString: testVector.n),
                e: Data(hexString: testVector.e),
                d: Data(hexString: testVector.d),
                p: Data(hexString: testVector.p),
                q: Data(hexString: testVector.q),
                parameters: testVector.parameters
            )
            let publicKey = try _RSA.BlindSigning.PublicKey(
                n: Data(hexString: testVector.n),
                e: Data(hexString: testVector.e),
                parameters: testVector.parameters
            )
            XCTAssertEqual(publicKey.derRepresentation, privateKey.publicKey.derRepresentation)
            // Prepare
            do {
                let message = try Data(hexString: testVector.msg)
                let preparedMessage = publicKey.prepare(message)
                switch testVector.parameters.preparation {
                case .identity:
                    XCTAssertEqual(preparedMessage.rawRepresentation, message)
                case .randomized:
                    XCTAssertEqual(preparedMessage.rawRepresentation.dropFirst(32), message)
                }
            }

            // Blind
            do {
                let preparedMessage = try _RSA.BlindSigning.PreparedMessage(rawRepresentation: Data(hexString: testVector.prepared_msg))
                let blindingResult = try publicKey.blind(preparedMessage)
                // NOTE: Sadly we can't validate the blinded message against the test vectors because BoringSSL doesn't
                // have the APIs we would need to specify a fixed salt value.
                XCTAssertEqual(blindingResult.blindedMessage.hexString.count, testVector.blinded_msg.count)
                XCTAssertEqual(blindingResult.inverse.rawRepresentation.hexString.count, testVector.inv.count)
            }

            // BlindSign
            do {
                let blindedMessage = try Data(hexString: testVector.blinded_msg)
                let blindSignature = try privateKey.blindSignature(for: blindedMessage)
                XCTAssertEqual(
                    blindSignature.rawRepresentation.hexString,
                    try Data(hexString: testVector.blind_sig).hexString
                )
            }

            // Finalize
            do {
                let blindSignature = try _RSA.BlindSigning.BlindSignature(rawRepresentation: Data(hexString: testVector.blind_sig))
                let preparedMessage = try _RSA.BlindSigning.PreparedMessage(rawRepresentation: Data(hexString: testVector.prepared_msg))
                let blindingInverse = try _RSA.BlindSigning.BlindingInverse(rawRepresentation: Data(hexString: testVector.inv))
                let signature = try publicKey.finalize(blindSignature, for: preparedMessage, blindingInverse: blindingInverse)
                XCTAssertEqual(
                    signature.rawRepresentation.hexString,
                    try Data(hexString: testVector.sig).hexString
                )
            }

            // Verification
            do {
                let signature = try _RSA.Signing.RSASignature(rawRepresentation: Data(hexString: testVector.sig))
                let preparedMessage = try _RSA.BlindSigning.PreparedMessage(rawRepresentation: Data(hexString: testVector.prepared_msg))
                XCTAssert(publicKey.isValidSignature(signature, for: preparedMessage))
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
        let blindedMessage = try Data(hexString: blindedMessageHexString)
        XCTAssertThrowsError(try privateKey.blindSignature(for: blindedMessage)) { error in
            guard let error = error as? CryptoKitError, case .incorrectParameterSize = error else {
                XCTFail("Unexpected error: \(error)")
                return
            }
        }
    }

    func testConstructKeyFromRSANumbers() throws {
        /// Check we can successfully construct keys from known valid values from a test vector.
        for testVector in RFC9474TestVector.allValues {
            _ = try _RSA.BlindSigning.PrivateKey(
                n: Data(hexString: testVector.n),
                e: Data(hexString: testVector.e),
                d: Data(hexString: testVector.d),
                p: Data(hexString: testVector.p),
                q: Data(hexString: testVector.q),
                parameters: testVector.parameters
            )
            _ = try _RSA.BlindSigning.PublicKey(
                n: Data(hexString: testVector.n),
                e: Data(hexString: testVector.e),
                parameters: testVector.parameters
            )
        }
        /// Also check that we can provide each argument as a different `ContiguousBytes` type.
        /// NOTE: these calls use `try?` because they are guaranteed to fail; we're just checking these calls compile.
        let bytesValues: [any ContiguousBytes] = [Data(), [UInt8]()]
        _ = try? _RSA.BlindSigning.PrivateKey(
            n: bytesValues.randomElement()!,
            e: bytesValues.randomElement()!,
            d: bytesValues.randomElement()!,
            p: bytesValues.randomElement()!,
            q: bytesValues.randomElement()!,
            parameters: .RSABSSA_SHA384_PSS_Randomized
        )
        _ = try? _RSA.BlindSigning.PublicKey(
            n: bytesValues.randomElement()!,
            e: bytesValues.randomElement()!,
            parameters: .RSABSSA_SHA384_PSS_Randomized
        )
    }

    func testConstructAndUseKeyFromRSANumbersWhileRecoveringPrimes() throws {
        let data = Array("hello, world!".utf8)

        for testVector in RFC9474TestVector.allValues {
            let key = try _RSA.BlindSigning.PrivateKey._createFromNumbers(
                n: Data(hexString: testVector.n),
                e: Data(hexString: testVector.e),
                d: Data(hexString: testVector.d),
                parameters: testVector.parameters
            )

            let preparedMessage = key.publicKey.prepare(data)
            let blindedMessage = try key.publicKey.blind(preparedMessage)
            let blindSignature = try key.blindSignature(for: blindedMessage.blindedMessage)
            let signature = try key.publicKey.finalize(blindSignature, for: preparedMessage, blindingInverse: blindedMessage.inverse)
            XCTAssert(key.publicKey.isValidSignature(signature, for: preparedMessage))
        }
    }

    func testGetKeyPrimitives() throws {
        for testVector in RFC9474TestVector.allValues {
            let n = try Data(hexString: testVector.n)
            let e = try Data(hexString: testVector.e)

            let primitives = try _RSA.BlindSigning.PublicKey(
                n: n, e: e,
                parameters: testVector.parameters
            ).getKeyPrimitives()
            XCTAssertEqual(primitives.modulus, n)
            XCTAssertEqual(primitives.publicExponent, e)
        }
    }
}
