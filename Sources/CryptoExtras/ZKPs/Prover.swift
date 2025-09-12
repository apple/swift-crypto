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
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct Prover<H2G: HashToGroup>: ProofParticipant {
    typealias Group = H2G.G
    var label: String
    var scalars: [Group.Scalar]
    var scalarLabels: [String]
    var points: [Group.Element]
    var pointLabels: [String]
    var constraints: [(PointVar, [(ScalarVar, PointVar)])]

    init(label: String) {
        self.label = label
        self.scalars = []
        self.scalarLabels = []
        self.points = []
        self.pointLabels = []
        self.constraints = []
    }

    mutating func appendScalar(label: String, assignment: Group.Scalar) -> ScalarVar {
        self.scalarLabels.append(label)
        self.scalars.append(assignment)
        return ScalarVar(index: self.scalars.count - 1)
    }

    func prove() throws -> Proof<H2G> {
        // Create a blinding scalar for each scalar variable.
        let blindings = (0..<self.scalars.count).map { _ in Group.Scalar.random }
        return try self.proveWithFixedRandomness(blindings: blindings)
    }

    // Pass in externally generated blinding values, for generating or testing against test vectors.
    func proveWithFixedRandomness(blindings: [Group.Scalar]) throws -> Proof<H2G> {
        // Perform size checks on proof fields.
        if (self.scalars.count != self.scalarLabels.count) || (self.points.count != self.pointLabels.count) {
            throw ZKPErrors.invalidProofFields
        }
        // Check that there is one blinding scalar for each allocated scalar variable.
        if (blindings.count != self.scalars.count) {
            throw ZKPErrors.invalidInputLength
        }

        // For each constraint, compute the blinded version of the constraint element.
        // Example: if the constraint is A=x*B, compute ABlind=xBlind*B for blinding scalar xBlind.
        // Example: if the constraint is A=x*B+y*C, compute ABlind=xBlind*B + yBlind*C for blinding scalars xBlind, yBlind.
        var blindedPoints: [Group.Element] = []
        var blindedPointsLabels: [String] = []
        for (constraintPoint, linearCombination) in self.constraints {
            // Check that all PointVar and ScalarVar variables in the constraint have been correctly allocated.
            if !(0..<self.points.count).contains(constraintPoint.index) {
                throw ZKPErrors.invalidVariableAllocation
            }
            for (scalarVar, pointVar) in linearCombination {
                if !(0..<self.scalars.count).contains(scalarVar.index) || !(0..<self.points.count).contains(pointVar.index) {
                    throw ZKPErrors.invalidVariableAllocation
                }
            }

            // TODO: expose the identity point from ECToolbox, and use `.reduce(0, +)` instead.
            // Compute the first multiplication in the constraint.
            let scalarIndex = linearCombination[0].0.index
            let pointIndex = linearCombination[0].1.index
            let firstBlindedPoint = blindings[scalarIndex] * self.points[pointIndex]

            // Compute the rest of the multiplications in the constraint.
            let blindedPoint = (linearCombination[1...]).map { (scalar, point) in
                blindings[scalar.index] * self.points[point.index]
            }.reduce(firstBlindedPoint, +)

            blindedPoints.append(blindedPoint)
            blindedPointsLabels.append(self.pointLabels[constraintPoint.index] + "-blind")
        }

        // Obtain a scalar challenge.
        let challenge = try Proof<H2G>.composeChallenge(label: self.label, points: self.points, pointLabels: self.pointLabels, blindedPoints: blindedPoints, blindedPointsLabels: blindedPointsLabels, scalarLabels: self.scalarLabels)

        // Compute response scalars from the challenge, scalars, and blindings.
        // Example: if the scalar is m, compute mResponse = mBlind - challenge * m for blinding scalar xBlind.
        var responses: [Group.Scalar] = []
        for (index, scalar) in self.scalars.enumerated() {
            let blinding = blindings[index]
            responses.append(blinding - challenge * scalar)
        }

        return Proof(challenge: challenge, responses: responses)
    }
}
