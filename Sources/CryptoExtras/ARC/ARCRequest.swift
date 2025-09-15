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
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
extension ARC {
    /// CredentialRequest consists of encryptions of the two client attributes, in the form of Pedersen commitments,
    /// along with a zero-knowledge proof of the following statements:
    /// 1. `m1Enc = m1 * G + r1 * H`, for private attribute `m1` and random request blinding `r1`
    /// 2. `m2Enc = m2 * G + r2 * H`, for private attribute `m2` and random request blinding `r2`
    struct CredentialRequest<H2G: HashToGroup> {
        typealias Group = H2G.G
        let m1Enc: Group.Element
        let m2Enc: Group.Element
        let proof: Proof<H2G>

        init(clientSecrets: ClientSecrets<Group.Scalar>, generatorG: Group.Element, generatorH: Group.Element, ciphersuite: Ciphersuite<H2G>) throws {
            let m1Enc = clientSecrets.m1 * generatorG + clientSecrets.r1 * generatorH
            let m2Enc = clientSecrets.m2 * generatorG + clientSecrets.r2 * generatorH

            // Create a prover, and allocate variables for the constrained scalars.
            var prover = Prover<H2G>(label: ciphersuite.domain + ciphersuite.domain + "CredentialRequest")
            let m1Var = prover.appendScalar(label: "m1", assignment: clientSecrets.m1)
            let m2Var = prover.appendScalar(label: "m2", assignment: clientSecrets.m2)
            let r1Var = prover.appendScalar(label: "r1", assignment: clientSecrets.r1)
            let r2Var = prover.appendScalar(label: "r2", assignment: clientSecrets.r2)

            // Allocate variables for the constrained points, and add the constraints.
            CredentialRequest.proofConstrain(participant: &prover, generatorG: generatorG, generatorH: generatorH, m1Enc: m1Enc, m2Enc: m2Enc, m1Var: m1Var, m2Var: m2Var, r1Var: r1Var, r2Var: r2Var)

            let proof = try prover.prove()
            self = CredentialRequest(m1Enc: m1Enc, m2Enc: m2Enc, proof: proof)
        }

        internal init(m1Enc: Group.Element, m2Enc: Group.Element, proof: Proof<H2G>) {
            self.m1Enc = m1Enc
            self.m2Enc = m2Enc
            self.proof = proof
        }

        func verify(generatorG: Group.Element, generatorH: Group.Element, ciphersuite: Ciphersuite<H2G>) throws -> Bool {
            // Check that the encrypted attributes were generated with nonzero `m` and `r` values.
            if (self.m1Enc == generatorG || self.m1Enc == generatorH || self.m1Enc == self.m1Enc + self.m1Enc) ||
               (self.m2Enc == generatorG || self.m2Enc == generatorH || self.m2Enc == self.m2Enc + self.m2Enc) {
                return false
            }

            // Create a verifier, and allocate variables for the constrained scalars.
            var verifier = Verifier<H2G>(label: ciphersuite.domain + ciphersuite.domain + "CredentialRequest")
            let m1Var = verifier.appendScalar(label: "m1")
            let m2Var = verifier.appendScalar(label: "m2")
            let r1Var = verifier.appendScalar(label: "r1")
            let r2Var = verifier.appendScalar(label: "r2")

            // Allocate variables for the constrained points, and add the constraints.
            CredentialRequest.proofConstrain(participant: &verifier, generatorG: generatorG, generatorH: generatorH, m1Enc: self.m1Enc, m2Enc: self.m2Enc, m1Var: m1Var, m2Var: m2Var, r1Var: r1Var, r2Var: r2Var)

            return try verifier.verify(proof: self.proof)
        }

        static internal func proofConstrain<P: ProofParticipant>(participant: inout P, generatorG: Group.Element, generatorH: Group.Element, m1Enc: Group.Element, m2Enc: Group.Element, m1Var: ScalarVar, m2Var: ScalarVar, r1Var: ScalarVar, r2Var: ScalarVar) {
            // Allocate point variables
            let genGVar = participant.appendPoint(label: "genG", assignment: generatorG)
            let genHVar = participant.appendPoint(label: "genH", assignment: generatorH)
            let m1EncVar = participant.appendPoint(label: "m1Enc", assignment: m1Enc)
            let m2EncVar = participant.appendPoint(label: "m2Enc", assignment: m2Enc)

            // 1. `m1Enc = m1 * G + r1 * H`, for private attribute `m1` and random request blinding `r1`
            participant.constrain(result: m1EncVar, linearCombination: [(m1Var, genGVar), (r1Var, genHVar)])
            // 2. `m2Enc = m2 * G + r2 * H`, for private attribute `m2` and random request blinding `r2`
            participant.constrain(result: m2EncVar, linearCombination: [(m2Var, genGVar), (r2Var, genHVar)])
        }

    }
}
