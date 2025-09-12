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
@testable import CryptoExtras
import XCTest

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
class ZKPToolboxTests: XCTestCase {
    typealias H2G = HashToCurveImpl<P384>
    typealias Group = H2G.G

    /// Tests the workflow for proof creation and verification, for a simple DL proof: A=x*B for a secret scalar x
    func DL1Workflow<Curve: SupportedCurveDetailsImpl>(CurveType _: Curve.Type) throws {
        // Prover's scope
        let (proof, point, result) = try {
            let point = Group.Element.random
            let scalar = Group.Scalar.random
            let result = scalar * point

            var prover = Prover<H2G>(label: "DL1Test")
            let scalarVar = prover.appendScalar(label: "scalar", assignment: scalar)
            let pointVar = prover.appendPoint(label: "point", assignment: point)
            let resultVar = prover.appendPoint(label: "result", assignment: result)
            prover.constrain(result: resultVar, linearCombination: [(scalarVar, pointVar)])
            let proof = try prover.prove()
            return (proof, point, result)
        }()

        // Verifier's scope
        var verifier = Verifier<H2G>(label: "DL1Test")
        let scalarVar = verifier.appendScalar(label: "scalar")
        let pointVar = verifier.appendPoint(label: "point", assignment: point)
        let resultVar = verifier.appendPoint(label: "result", assignment: result)
        verifier.constrain(result: resultVar, linearCombination: [(scalarVar, pointVar)])
        let proofVerifies = try verifier.verify(proof: proof)
        XCTAssert(proofVerifies)

        // Test that incorrect proof elements causes proof verification to fail
        var failVerifier = Verifier<H2G>(label: "DL1Test")
        let failScalarVar = failVerifier.appendScalar(label: "scalar")
        let _ = failVerifier.appendPoint(label: "point", assignment: point)
        let failResultVar = failVerifier.appendPoint(label: "result", assignment: result)
        failVerifier.constrain(result: failResultVar, linearCombination: [(failScalarVar, failResultVar)]) // Incorrect point
        let failProofVerifies = try failVerifier.verify(proof: proof)
        XCTAssertFalse(failProofVerifies)
    }

    func testDL1() throws {
        try DL1Workflow(CurveType: P256.self)
        try DL1Workflow(CurveType: P384.self)
        try DL1Workflow(CurveType: P521.self)
    }

    /// Allocate group element variables and define the constraints for a DLEQ proof:
    /// result1 = scalar * point1 and result2 = scalar * point2
    /// such that log_point1(result1)==log_point2(result2), for a secret scalar.
    func DLEqualityConstrain<P: ProofParticipant>(participant: inout P, scalarVar: ScalarVar,
                                            point1: Group.Element, result1: Group.Element,
                                            point2: Group.Element, result2: Group.Element) {
        let point1Var = participant.appendPoint(label: "point1", assignment: point1)
        let result1Var = participant.appendPoint(label: "result1", assignment: result1)
        let point2Var = participant.appendPoint(label: "point2", assignment: point2)
        let result2Var = participant.appendPoint(label: "result2", assignment: result2)
        participant.constrain(result: result1Var, linearCombination: [(scalarVar, point1Var)])
        participant.constrain(result: result2Var, linearCombination: [(scalarVar, point2Var)])
    }

    /// Tests the workflow for proof creation and verification, for a simple DLEQ proof:
    /// For a secret scalar x, the relation between B=x*A and D=x*C is such that log_A(B)==log_C(D)
    func DLEqualityWorkflow<Curve: SupportedCurveDetailsImpl>(CurveType _: Curve.Type) throws {
        // Prover's scope
        let (proof, point1, point2, result1, result2) = try {
            let point1 = Group.Element.random
            let point2 = Group.Element.random
            let scalar = Group.Scalar.random
            let result1 = scalar * point1
            let result2 = scalar * point2

            var prover = Prover<H2G>(label: "DLEqualityTest")
            let scalarVar = prover.appendScalar(label: "scalar", assignment: scalar)
            DLEqualityConstrain(participant: &prover, scalarVar: scalarVar, point1: point1, result1: result1, point2: point2, result2: result2)
            let proof = try prover.prove()
            return (proof, point1, point2, result1, result2)
        }()

        // Verifier's scope
        var verifier = Verifier<H2G>(label: "DLEqualityTest")
        let scalarVar = verifier.appendScalar(label: "scalar")
        DLEqualityConstrain(participant: &verifier, scalarVar: scalarVar, point1: point1, result1: result1, point2: point2, result2: result2)
        let proofVerifies = try verifier.verify(proof: proof)
        XCTAssert(proofVerifies)

        // Test that incorrect ProofParticipant label causes proof verification to fail
        var failVerifier = Verifier<H2G>(label: "WrongTestLabel")
        let failScalarVar = failVerifier.appendScalar(label: "scalar")
        DLEqualityConstrain(participant: &failVerifier, scalarVar: failScalarVar, point1: point1, result1: result1, point2: point2, result2: result2)
        let failProofVerifies = try failVerifier.verify(proof: proof)
        XCTAssertFalse(failProofVerifies)
    }

    func testDLEquality() throws {
        try DLEqualityWorkflow(CurveType: P256.self)
        try DLEqualityWorkflow(CurveType: P384.self)
        try DLEqualityWorkflow(CurveType: P521.self)
    }

    /// Tests the workflow for proof creation and verification, for a commitment proof: A=x*B+y*C for secret scalars x, y
    func DL2Workflow<Curve: SupportedCurveDetailsImpl>(CurveType _: Curve.Type) throws {
        // Prover's scope
        let (proof, point1, point2, result) = try {
            let point1 = Group.Element.random
            let point2 = Group.Element.random
            let scalar1 = Group.Scalar.random
            let scalar2 = Group.Scalar.random
            let result = scalar1 * point1 + scalar2 * point2

            var prover = Prover<H2G>(label: "DL2Test")
            let scalar1Var = prover.appendScalar(label: "scalar1", assignment: scalar1)
            let scalar2Var = prover.appendScalar(label: "scalar2", assignment: scalar2)
            let point1Var = prover.appendPoint(label: "point1", assignment: point1)
            let point2Var = prover.appendPoint(label: "point2", assignment: point2)
            let resultVar = prover.appendPoint(label: "result", assignment: result)
            prover.constrain(result: resultVar, linearCombination: [(scalar1Var, point1Var), (scalar2Var, point2Var)])
            let proof = try prover.prove()
            return (proof, point1, point2, result)
        }()

        // Verifier's scope
        var verifier = Verifier<H2G>(label: "DL2Test")
        let scalar1Var = verifier.appendScalar(label: "scalar1")
        let scalar2Var = verifier.appendScalar(label: "scalar2")
        let point1Var = verifier.appendPoint(label: "point1", assignment: point1)
        let point2Var = verifier.appendPoint(label: "point2", assignment: point2)
        let resultVar = verifier.appendPoint(label: "result", assignment: result)
        verifier.constrain(result: resultVar, linearCombination: [(scalar1Var, point1Var), (scalar2Var, point2Var)])
        let proofVerifies = try verifier.verify(proof: proof)
        XCTAssert(proofVerifies)
    }

    func testDL2() throws {
        try DL2Workflow(CurveType: P256.self)
        try DL2Workflow(CurveType: P384.self)
        try DL2Workflow(CurveType: P521.self)
    }

    /// Tests an empty workflow, where no variables are allocated.
    func EmptyWorkflow<Curve: SupportedCurveDetailsImpl>(CurveType _: Curve.Type) throws {
        // Prover's scope
        let proof = try {
            let prover = Prover<H2G>(label: "EmptyTest")
            let proof = try prover.prove()
            return proof
        }()

        // Verifier's scope
        let verifier = Verifier<H2G>(label: "EmptyTest")
        let result = try verifier.verify(proof: proof)
        XCTAssert(result)
    }

    func testEmpty() throws {
        try EmptyWorkflow(CurveType: P256.self)
        try EmptyWorkflow(CurveType: P384.self)
        try EmptyWorkflow(CurveType: P521.self)
    }
}
