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
@testable import CryptoExtras  // NOTE: @testable import, to inject fixed values from test vectors.
import XCTest

extension OPRFSuite {
    static func load(from fileURL: URL) throws -> [Self] {
        let json = try Data(contentsOf: fileURL)
        let decoder = JSONDecoder()
        return try decoder.decode([Self].self, from: json)
    }

    static let allValues: [Self] = try! OPRFSuite.load(from: URL(
        fileURLWithPath: "OPRFVectors/OPRFVectors-VOPRFDraft19.json",
        relativeTo: URL(fileURLWithPath: #filePath)
    ))

    static var P384_SHA384_VORPF: Self {
        self.allValues.filter { $0.identifier == "P384-SHA384" && $0.mode == 1 }.first!
    }
}

@available(macOS 13.0, iOS 16.0, tvOS 16.0, watchOS 9.0, *)
final class VOPRFAPITests: XCTestCase {
    func testVectors() throws {
        try testVectorsVOPRF(suite: .P384_SHA384_VORPF)
        try testVectorsPRF(suite: .P384_SHA384_VORPF)
    }

    func testVectorsVOPRF(suite: OPRFSuite) throws {
        for vector in suite.vectors.filter({ $0.Batch == 1 }) {
            // [Server] Create the key-pair.
            let privateKey = try P384._VOPRF.PrivateKey(rawRepresentation: Data(hexString: suite.skSm))

            // [Client] Obtain public key.
            let publicKey = privateKey.publicKey

            // [Client] Have a private input they wish to use.
            let privateInput = try Data(hexString: vector.Input)

            // [Client] Blind the private input and send the blinded element to the server.
            // TODO: should we make this the nomminal type?
            let fixedBlind = try P384._VOPRF.H2G.G.Scalar(bytes: Data(hexString: vector.Blind))
            let blindedInput = try publicKey.blind(privateInput, with: fixedBlind)

            // [Client -> Server] Send the blinded element.
            let blindedElementBytes = blindedInput.blindedElement.oprfRepresentation

            // [CHECK] Blinded element matches test vector.
            XCTAssertEqual(blindedElementBytes.hexString, vector.BlindedElement)

            // [Server] Receive the blinded element.
            let blindedElememt = try P384._VOPRF.BlindedElement(oprfRepresentation: blindedElementBytes)

            // [Server] Blind evaluate the blinded element and send the evaluation, along with the proof, to the client.
            let fixedProofScalar = try P384._VOPRF.H2G.G.Scalar(bytes: Data(hexString: vector.Proof!.r))
            XCTAssertNil(vector.Info, "VOPRF mode shouldn't have info.")
            let blindEvaluation = try privateKey.evaluate(blindedElememt, using: fixedProofScalar)

            // [CHECK] Evaluated element matches test vector.
            XCTAssertEqual(blindEvaluation.evaluatedElement.oprfRepresentation.hexString, vector.EvaluationElement)

            // [CHECK] Proof matches test vector.
            XCTAssertEqual(blindEvaluation.proof.rawRepresentation.hexString, vector.Proof?.proof)

            // [Server -> Client] Send the serialized blind evaluation.
            let blindEvaluationBytes = blindEvaluation.rawRepresentation

            // [Client] Receive the blind evaluation.
            let deserializedBlindEvaluation = try P384._VOPRF.BlindEvaluation(rawRepresentation: blindEvaluationBytes)

            // [Client] Finalize the evaluation by verifying the proof and unblinding to produce the output.
            let output = try publicKey.finalize(blindedInput, using: deserializedBlindEvaluation)

            // [CHECK] Final output matches test vector.
            XCTAssertEqual(output.hexString, vector.Output)
        }
    }

    func testVectorsPRF(suite: OPRFSuite) throws {
        for vector in suite.vectors.filter({ $0.Batch == 1 }) {
            // [Server] Create the key-pair.
            let privateKey = try P384._VOPRF.PrivateKey(rawRepresentation: Data(hexString: suite.skSm))

            // [Server] Have an input they wish to use.
            let input = try Data(hexString: vector.Input)

            // [Server] Compute the PRF for the input, without blinding or proof generation.
            let output = try privateKey.evaluate(input)

            // [CHECK] Final output matches test vector.
            XCTAssertEqual(output.hexString, vector.Output)
        }
    }
}
