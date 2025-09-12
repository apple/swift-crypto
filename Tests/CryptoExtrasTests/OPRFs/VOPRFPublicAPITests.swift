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
import Crypto
import CryptoExtras  // NOTE: No @testable import, because we want to test the public API.
import XCTest

@available(macOS 13.0, iOS 16.0, tvOS 16.0, watchOS 9.0, *)
final class VOPRFPublicAPITests: XCTestCase {

    func testEndToEndVOPRF() throws {
        // [Server] Create the key-pair (other initializers are available).
        let privateKey = P384._VOPRF.PrivateKey()

        // [Client] Obtain public key (other initializers are available).
        let publicKey = privateKey.publicKey

        // [Client] Have a private input they wish to use.
        let privateInput = Data("This is some input data".utf8)

        // [Client] Blind the private input and send the blinded element to the server.
        let blindedInput = try publicKey.blind(privateInput)

        // [Client -> Server] Send the blinded element.
        let blindedElementBytes = blindedInput.blindedElement.oprfRepresentation

        // [Server] Receive the blinded element.
        let blindedElememt = try P384._VOPRF.BlindedElement(oprfRepresentation: blindedElementBytes)

        // [Server] Blind evaluate the blinded element and send the evaluation, along with the proof, to the client.
        let blindEvaluation = try privateKey.evaluate(blindedElememt)

        // [Server -> Client] Send the serialized blind evaluation.
        let blindEvaluationBytes = blindEvaluation.rawRepresentation

        // [Client] Receive the blind evaluation.
        let deserializedBlindEvaluation = try P384._VOPRF.BlindEvaluation(rawRepresentation: blindEvaluationBytes)

        // [Client] Finalize the evaluation by verifying the proof and unblinding to produce the output.
        let _: Data = try publicKey.finalize(blindedInput, using: deserializedBlindEvaluation)
    }

    func testAccessToEvaluatedElementAndProof() throws {
        /// In RFC 9497, the `BlindEvaluate` routine returns both `evaluatedElement` and `proof`, which are both later
        /// provided to `Finalize`.
        ///
        /// For our API, these are bundled together into a `BlindEvaluation`, and since both are used in the final step,
        /// our `finalize` API takes the composite type too, to guide correct usage.
        ///
        /// However, for use cases that require distinct access to the evaluated element and the proof we also expose
        /// these properties as API.
        ///
        /// - See: https://www.rfc-editor.org/rfc/rfc9497.html#section-3.3.2-2
        let vector = OPRFSuite.P384_SHA384_VORPF.vectors.first!
        let evaluatedElement = try Data(hexString: vector.EvaluationElement)
        let proof = try Data(hexString: vector.Proof!.proof)
        let blindEvaluation = try P384._VOPRF.BlindEvaluation(rawRepresentation: evaluatedElement + proof)
        XCTAssertEqual(blindEvaluation.evaluatedElement.oprfRepresentation, evaluatedElement)
        XCTAssertEqual(blindEvaluation.proof.rawRepresentation, proof)
    }

    func testEndToEndPRF() throws {
        // [Server] Create the key-pair (other initializers are available).
        let privateKey = P384._VOPRF.PrivateKey()

        // [Server] Have an input they wish to use.
        let input = Data("This is some input data".utf8)

        // [Server] Compute the PRF for the input, without blinding or proof generation.
        let _: Data = try privateKey.evaluate(input)
    }
}
