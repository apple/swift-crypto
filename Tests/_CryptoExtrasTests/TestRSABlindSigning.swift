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
