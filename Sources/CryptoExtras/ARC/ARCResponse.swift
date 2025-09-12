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
    /// CredentialResponse consists of a MACGGM evaluation over a Pedersen commitment to a private attribute,
    /// along with the corresponding proof that it was calculated correctly over the expected key commitments:
    /// 1. `X0 = x0 * generatorG + x0Blinding * generatorH`
    /// 2. `X1 = x1 * generatorH`
    /// 3. `X2 = x2 * generatorH`
    /// 4. `X0Aux = b * x0Blinding * generatorH`
    ///   4a. `HAux = b * generatorH`
    ///   4b: `X0Aux = x0Blinding * HAux`
    /// 5. `X1Aux = b * x1 * generatorH`
    ///   5a.  `X1Aux = b * X1 (X1 = x1 * generatorH)`
    ///   5b.  `X1Aux = t1 * H (t1 = b * x1)`
    /// 6. `X2Aux = b * x2 * generatorH`
    ///   6a. `X2Aux = b * X2 (X2 = x2 * generatorH)`
    ///   6b. `X2Aux = t2 * H (t2 = b * x2)`
    /// 7. `U = b * generatorG`
    /// 8. `encUPrime = b * (X0 + x1 * Enc(m1) + x2 * Enc(m2))`
    struct CredentialResponse<H2G: HashToGroup> {
        typealias Group = H2G.G
        let U: Group.Element
        let encUPrime: Group.Element
        let X0Aux: Group.Element
        let X1Aux: Group.Element
        let X2Aux: Group.Element
        let HAux: Group.Element
        let proof: Proof<H2G>

        init(
            request: CredentialRequest<H2G>,
            serverPrivateKey: ServerPrivateKey<Group.Scalar>,
            serverPublicKey: ServerPublicKey<H2G>,
            generatorG: Group.Element,
            generatorH: Group.Element,
            b: Group.Scalar = Group.Scalar.random,
            ciphersuite: Ciphersuite<H2G>
        ) throws {
            let U = b * generatorG
            let X0Aux = b * serverPrivateKey.x0Blinding * generatorH
            let X1Aux = b * serverPublicKey.X1
            let X2Aux = b * serverPublicKey.X2
            let HAux = b * generatorH

            // Enc(U') = b * (Enc(x0) + x1 * Enc(m1) + x2 * Enc(m2)), for a homomorphic encryption scheme
            //         = b * (X0 + x1 * request.m1Enc + x2 * request.m2Enc)
            let encUPrime = b * (serverPublicKey.X0 + serverPrivateKey.x1 * request.m1Enc + serverPrivateKey.x2 * request.m2Enc)

            // Create a prover, and allocate variables for the constrained scalars.
            var prover = Prover<H2G>(label: ciphersuite.domain + ciphersuite.domain + "CredentialResponse")
            let x0Var = prover.appendScalar(label: "x0", assignment: serverPrivateKey.x0)
            let x1Var = prover.appendScalar(label: "x1", assignment: serverPrivateKey.x1)
            let x2Var = prover.appendScalar(label: "x2", assignment: serverPrivateKey.x2)
            let x0BlindingVar = prover.appendScalar(label: "x0Blinding", assignment: serverPrivateKey.x0Blinding)
            let bVar = prover.appendScalar(label: "b", assignment: b)
            let t1Var = prover.appendScalar(label: "t1", assignment: b * serverPrivateKey.x1)
            let t2Var = prover.appendScalar(label: "t2", assignment: b * serverPrivateKey.x2)

            // Allocate variables for the constrained points, and add the constraints.
            CredentialResponse.proofConstrain(participant: &prover, request: request, generatorG: generatorG, generatorH: generatorH, U: U, encUPrime: encUPrime, X0: serverPublicKey.X0, X1: serverPublicKey.X1, X2: serverPublicKey.X2, X0Aux: X0Aux, X1Aux: X1Aux, X2Aux: X2Aux, HAux: HAux, x0Var: x0Var, x0BlindingVar: x0BlindingVar, x1Var: x1Var, x2Var: x2Var, bVar: bVar, t1Var: t1Var, t2Var: t2Var)

            let proof = try prover.prove()
            self = CredentialResponse(U: U, encUPrime: encUPrime, X0Aux: X0Aux, X1Aux: X1Aux, X2Aux: X2Aux, HAux: HAux, proof: proof)
        }

        internal init(
            U: Group.Element,
            encUPrime: Group.Element,
            X0Aux: Group.Element,
            X1Aux: Group.Element,
            X2Aux: Group.Element,
            HAux: Group.Element,
            proof: Proof<H2G>
        ) {
            self.U = U
            self.encUPrime = encUPrime
            self.X0Aux = X0Aux
            self.X1Aux = X1Aux
            self.X2Aux = X2Aux
            self.HAux = HAux
            self.proof = proof
        }

        func verify(request: CredentialRequest<H2G>, serverPublicKey: ServerPublicKey<H2G>, generatorG: Group.Element, generatorH: Group.Element, ciphersuite: Ciphersuite<H2G>) throws -> Bool {
            // Check that U, encUPrime are not 0
            if (self.U == self.U + self.U) || (self.encUPrime == self.encUPrime + self.encUPrime) {
                return false
            }

            // Create a verifier, and allocate variables for the constrained scalars.
            var verifier = Verifier<H2G>(label: ciphersuite.domain + ciphersuite.domain + "CredentialResponse")
            let x0Var = verifier.appendScalar(label: "x0")
            let x1Var = verifier.appendScalar(label: "x1")
            let x2Var = verifier.appendScalar(label: "x2")
            let x0BlindingVar = verifier.appendScalar(label: "x0Blinding")
            let bVar = verifier.appendScalar(label: "b")
            let t1Var = verifier.appendScalar(label: "t1")
            let t2Var = verifier.appendScalar(label: "t2")

            // Allocate variables for the constrained points, and add the constraints.
            CredentialResponse.proofConstrain(participant: &verifier, request: request, generatorG: generatorG, generatorH: generatorH, U: U, encUPrime: encUPrime, X0: serverPublicKey.X0, X1: serverPublicKey.X1, X2: serverPublicKey.X2, X0Aux: X0Aux, X1Aux: X1Aux, X2Aux: X2Aux, HAux: HAux, x0Var: x0Var, x0BlindingVar: x0BlindingVar, x1Var: x1Var, x2Var: x2Var, bVar: bVar, t1Var: t1Var, t2Var: t2Var)

            return try verifier.verify(proof: self.proof)
        }

        static internal func proofConstrain<P: ProofParticipant>(participant: inout P, request: CredentialRequest<H2G>, generatorG: Group.Element, generatorH: Group.Element, U: Group.Element, encUPrime: Group.Element, X0: Group.Element, X1: Group.Element, X2: Group.Element, X0Aux: Group.Element, X1Aux: Group.Element, X2Aux: Group.Element, HAux: Group.Element, x0Var: ScalarVar, x0BlindingVar: ScalarVar, x1Var: ScalarVar, x2Var: ScalarVar, bVar: ScalarVar, t1Var: ScalarVar, t2Var: ScalarVar) {
            // Allocate point variables
            let genGVar = participant.appendPoint(label: "genG", assignment: generatorG)
            let genHVar = participant.appendPoint(label: "genH", assignment: generatorH)
            let m1EncVar = participant.appendPoint(label: "m1Enc", assignment: request.m1Enc)
            let m2EncVar = participant.appendPoint(label: "m2Enc", assignment: request.m2Enc)
            let UVar = participant.appendPoint(label: "U", assignment: U)
            let encUPrimeVar = participant.appendPoint(label: "encUPrime", assignment: encUPrime)
            let X0Var = participant.appendPoint(label: "X0", assignment: X0)
            let X1Var = participant.appendPoint(label: "X1", assignment: X1)
            let X2Var = participant.appendPoint(label: "X2", assignment: X2)
            let X0AuxVar = participant.appendPoint(label: "X0Aux", assignment: X0Aux)
            let X1AuxVar = participant.appendPoint(label: "X1Aux", assignment: X1Aux)
            let X2AuxVar = participant.appendPoint(label: "X2Aux", assignment: X2Aux)
            let HAuxVar = participant.appendPoint(label: "HAux", assignment: HAux)

            // 1. X0 = x0 * generatorG + x0Blinding * generatorH
            participant.constrain(result: X0Var, linearCombination: [(x0Var, genGVar), (x0BlindingVar, genHVar)])
            // 2. X1 = x1 * generatorH
            participant.constrain(result: X1Var, linearCombination: [(x1Var, genHVar)])
            // 3. X2 = x2 * generatorH
            participant.constrain(result: X2Var, linearCombination: [(x2Var, genHVar)])

            // 4. X0Aux = b * x0Blinding * generatorH
            // 4a. HAux = b * generatorH
            participant.constrain(result: HAuxVar, linearCombination: [(bVar, genHVar)])
            // 4b: X0Aux = x0Blinding * HAux
            participant.constrain(result: X0AuxVar, linearCombination: [(x0BlindingVar, HAuxVar)])

            // 5. X1Aux = b * x1 * generatorH
            // 5b. X1Aux = t1 * generatorH, where t1 = b*x1 (NOTE: this is out of order in the spec & poc.)
            participant.constrain(result: X1AuxVar, linearCombination: [(t1Var, genHVar)])
            // 5a. X1Aux = b * X1, where X1 = x1 * generatorH (as constrained in #2)
            participant.constrain(result: X1AuxVar, linearCombination: [(bVar, X1Var)])

            // 6. X2Aux = b * x2 * generatorH
            // 6a. X2Aux = b * X2, where X2 = x2 * generatorH (as constrained in #3)
            participant.constrain(result: X2AuxVar, linearCombination: [(bVar, X2Var)])
            // 6b. X2Aux = t2 * generatorH, where t2 = b*x2
            participant.constrain(result: X2AuxVar, linearCombination: [(t2Var, genHVar)])

            // 7. U = b * generatorG
            participant.constrain(result: UVar, linearCombination: [(bVar, genGVar)])
            // 8. encUPrime = b * (X0Var + x1 * request.encAttribute)
            // 8. encUPrime = b * (X0 + x1 * Enc(m1) + x2 * Enc(m2))
            // simplified: encUPrime = b * X0 + t1 * m1Enc + t2 * m2Enc, since t1 = b * x1 and t2 = b * x2
            participant.constrain(result: encUPrimeVar, linearCombination: [(bVar, X0Var), (t1Var, m1EncVar), (t2Var, m2EncVar)])
        }
    }
}
