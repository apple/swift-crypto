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
import CryptoExtras  // NOTE: No @testable import, because we want to test the public API.

final class TestRSABlindSigningAPI: XCTestCase {
    func testEndToEnd() throws {
        let allNamedRFC9474Variants: [_RSA.BlindSigning.Parameters] = [
            .RSABSSA_SHA384_PSSZERO_Deterministic,
            .RSABSSA_SHA384_PSSZERO_Randomized,
            .RSABSSA_SHA384_PSS_Deterministic,
            .RSABSSA_SHA384_PSS_Randomized,
        ]
        let keySizes: [_RSA.Signing.KeySize] = [
            .bits2048,
            .bits3072,
            .bits4096,
        ]
        for parameters in allNamedRFC9474Variants {
            for keySize in keySizes {
                // [Issuer] Create key-pair (other initializers are available).
                let privateKey = try _RSA.BlindSigning.PrivateKey(keySize: keySize, parameters: parameters)

                // [Client] Create public key (other initializers are available).
                let publicKey = privateKey.publicKey

                // [Client] Have a message they wish to use.
                let message = Data("This is some input data".utf8)

                // [Client] Prepare the message.
                let preparedMessage = publicKey.prepare(message)

                // [Client] Blind the message to send to the server and get its blinding inverse.
                let blindingResult = try publicKey.blind(preparedMessage)

                // [Issuer] Blind sign, construting the blinded message from the bytes received from the client.
                let blindSignature = try privateKey.blindSignature(for: blindingResult.blindedMessage)

                // [Client] Finalize using the blind inverse to unblind the signature.
                let unblindedSignature = try publicKey.finalize(blindSignature, for: preparedMessage, blindingInverse: blindingResult.inverse)

                // [Verifier] Verify the unblinded signature.
                XCTAssert(publicKey.isValidSignature(unblindedSignature, for: preparedMessage))
            }
        }
    }
}
