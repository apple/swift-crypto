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
    /// Presentation consists of a commitment to a MACGGC evaluation over two attributes,
    /// a commitment to one of the attributes, a tag and its public inputs (presentationContext, nonce),
    /// along with a zero-knowledge proof of the following statements:
    /// 1. `m1Commit = m1 * U + z * generatorH`, for attribute `m1` and random `z`.
    /// 2. `V = z * X1 - r * generatorG`, for random `z` and `r`.
    /// 3. `H2G(presentationContext) = m1 * tag + nonce * tag`
    /// 4. `m1Tag = m1 * tag`
    struct Presentation<H2G: HashToGroup> {
        typealias Group = H2G.G
        /// Generator over which `m1Commit` commits to `m1`.
        let U: Group.Element
        /// Commitment to the MACGGC evaluation over the client attributes.
        let UPrimeCommit: Group.Element
        /// Commitment to `m1` over `U`.
        let m1Commit: Group.Element
        /// Group element `tag = (m1 + nonce)^(-1) * H2G(presentationContext)`, where `m1` is committed to by `m1Commit`.
        let tag: Group.Element
        /// Proof of correct computation of U, UPrimeCommit, m1Commit, and tag, given the presentationContext, nonce, generators, and secrets.
        let proof: Proof<H2G>

        init(credential: Credential<H2G>, a: Group.Scalar = Group.Scalar.random, r: Group.Scalar = Group.Scalar.random, z: Group.Scalar = Group.Scalar.random, presentationContext: Data, nonce: Int, generatorG: Group.Element, generatorH: Group.Element) throws {
            // Randomize (U, UPrime)
            let U = a * credential.U
            let m1Commit = credential.m1 * U + z * generatorH
            let UPrime = a * credential.UPrime
            let UPrimeCommit = UPrime + r * generatorG
            let V = z * credential.X1 - r * generatorG

            // Create tag: (m1 + nonce)^(-1) * H2G(presentationContext)
            let nonceScalar = try Group.Scalar(bytes: I2OSP(value: nonce, outputByteCount: credential.ciphersuite.scalarByteCount), reductionIsModOrder: true)
            let inverse = (nonceScalar + credential.m1) ^ (-1)
            let T = H2G.hashToGroup(presentationContext, domainSeparationString: Data(("HashToGroup-" + credential.ciphersuite.domain + "Tag").utf8))
            let tag = inverse * T

            // m1Tag is a helper element in the ZKP, and is needed to ensure the
            // client-claimed nonce is equal to the nonce used to compute the tag.
            let m1Tag = credential.m1 * tag

            // Create a prover, and allocate variables for the constrained scalars.
            var prover = Prover<H2G>(label: credential.ciphersuite.domain + credential.ciphersuite.domain + "CredentialPresentation")
            let m1Var = prover.appendScalar(label: "m1", assignment: credential.m1)
            let zVar = prover.appendScalar(label: "z", assignment: z)
            let rNegVar = prover.appendScalar(label: "-r", assignment: -r)
            let nonceVar = prover.appendScalar(label: "nonce", assignment: nonceScalar)

            // Allocate variables for the constrained points, and add the constraints.
            Presentation.proofConstrain(participant: &prover, generatorG: generatorG, generatorH: generatorH, U: U, UPrimeCommit: UPrimeCommit, m1Commit: m1Commit, V: V, X1: credential.X1, T: T, tag: tag, m1Tag: m1Tag, m1Var: m1Var, zVar: zVar, rNegVar: rNegVar, nonceVar: nonceVar)

            let proof = try prover.prove()
            self = Presentation(U: U, UPrimeCommit: UPrimeCommit, m1Commit: m1Commit, tag: tag, proof: proof)
        }

        internal init(U: Group.Element, UPrimeCommit: Group.Element, m1Commit: Group.Element, tag: Group.Element, proof: Proof<H2G>) {
            self.U = U
            self.UPrimeCommit = UPrimeCommit
            self.m1Commit = m1Commit
            self.tag = tag
            self.proof = proof
        }

        /**
         - Parameters:
            - serverPrivateKey: A collection of scalars representing the server private key, which it needs to verify the presentation.
            - X1: Group element that is a commitment to x1, one of the server secrets.
            - m2: Public value that server provides for verification.
            - presentationContext: Data that is concatenated with the nonce and hashed to a group element, as input to the tag.
            - presentationLimit: Integer representing the valid nonce range: `[0, presentationLimit)`.
            - nonce: Integer which is used for rate limiting, which should be in `[0, presentationLimit)`.
            - generatorG: Public generator G
            - generatorH: Public generator H
            - ciphersuite: The ciphersuite for ARC
         - Returns: a boolean for if the tag is valid and the tag proof verifies correctly.
         */
        func verify(serverPrivateKey: ServerPrivateKey<Group.Scalar>, X1: Group.Element, m2: Group.Scalar, presentationContext: Data, presentationLimit: Int, nonce: Int, generatorG: Group.Element, generatorH: Group.Element, ciphersuite: Ciphersuite<H2G>) throws -> Bool {
            if nonce < 0 || nonce >= presentationLimit {
                return false // nonce is outside of the presentationLimit
            }


            if (self.U == self.U + self.U) || (self.UPrimeCommit == self.UPrimeCommit + self.UPrimeCommit) {
                return false // U or UPrimeCommit are 0
            }
            let V = serverPrivateKey.x0 * self.U + serverPrivateKey.x1 * self.m1Commit + serverPrivateKey.x2 * m2 * self.U - self.UPrimeCommit

            // Recompute T = H2G(presentationContext)
            let T = H2G.hashToGroup(presentationContext, domainSeparationString: Data(("HashToGroup-" + ciphersuite.domain + "Tag").utf8))

            // Recompute m1Tag = H2G(presentationContext) - nonce * tag
            var m1Tag = T
            for _ in 0..<nonce { m1Tag = m1Tag - self.tag }

            // Create a verifier, and allocate variables for the constrained scalars.
            var verifier = Verifier<H2G>(label: ciphersuite.domain + ciphersuite.domain + "CredentialPresentation")
            let m1Var = verifier.appendScalar(label: "m1")
            let zVar = verifier.appendScalar(label: "z")
            let rNegVar = verifier.appendScalar(label: "-r")
            let nonceVar = verifier.appendScalar(label: "nonce")

            // Allocate variables for the constrained points, and add the constraints.
            Presentation.proofConstrain(participant: &verifier, generatorG: generatorG, generatorH: generatorH, U: self.U, UPrimeCommit: self.UPrimeCommit, m1Commit: self.m1Commit, V: V, X1: X1, T: T, tag: self.tag, m1Tag: m1Tag, m1Var: m1Var, zVar: zVar, rNegVar: rNegVar, nonceVar: nonceVar)

            return try verifier.verify(proof: self.proof)
        }

        static internal func proofConstrain<P: ProofParticipant>(participant: inout P, generatorG: Group.Element, generatorH: Group.Element, U: Group.Element, UPrimeCommit: Group.Element, m1Commit: Group.Element, V: Group.Element, X1: Group.Element, T: Group.Element, tag: Group.Element, m1Tag: Group.Element, m1Var: ScalarVar, zVar: ScalarVar, rNegVar: ScalarVar, nonceVar: ScalarVar) {
            // Allocate point variables
            let genGVar = participant.appendPoint(label: "genG", assignment: generatorG)
            let genHVar = participant.appendPoint(label: "genH", assignment: generatorH)
            let UVar = participant.appendPoint(label: "U", assignment: U)
            // UPrimeCommit does not have to be explicitly constrained in the ZKP, as it is used in calculation of V which is constrained.
            let _ = participant.appendPoint(label: "UPrimeCommit", assignment: UPrimeCommit)
            let m1CommitVar = participant.appendPoint(label: "m1Commit", assignment: m1Commit)
            let VVar = participant.appendPoint(label: "V", assignment: V)
            let X1Var = participant.appendPoint(label: "X1", assignment: X1)
            let tagVar = participant.appendPoint(label: "tag", assignment: tag)
            let TVar = participant.appendPoint(label: "genT", assignment: T)
            let m1TagVar = participant.appendPoint(label: "m1Tag", assignment: m1Tag)

            // 1. `m1Commit = m1 * U + z * generatorH`, for attribute `m1` and random `z`.
            participant.constrain(result: m1CommitVar, linearCombination: [(m1Var, UVar), (zVar, genHVar)])
            // 2. `V = z * X1 - r * generatorG`, for random `z` and `r`.
            // Simplified: `V = z * X1 + (-r) * generatorG`
            participant.constrain(result: VVar, linearCombination: [(zVar, X1Var), (rNegVar, genGVar)])
            /// 3. `H2G(presentationContext) = m1 * tag + nonce * tag`
            participant.constrain(result: TVar, linearCombination: [(m1Var, tagVar), (nonceVar, tagVar)])
            /// 4. `m1Tag = m1 * tag`
            participant.constrain(result: m1TagVar, linearCombination: [(m1Var, tagVar)])
        }
    }
}
