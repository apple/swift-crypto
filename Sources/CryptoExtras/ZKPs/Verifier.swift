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
struct Verifier<H2G: HashToGroup>: ProofParticipant {
    typealias Group = H2G.G
    var label: String
    var scalarLabels: [String]
    var points: [Group.Element]
    var pointLabels: [String]
    var constraints: [(PointVar, [(ScalarVar, PointVar)])]

    init(label: String) {
        self.label = label
        self.scalarLabels = []
        self.points = []
        self.pointLabels = []
        self.constraints = []
    }

    mutating func appendScalar(label: String) -> ScalarVar {
        self.scalarLabels.append(label)
        return ScalarVar(index: self.scalarLabels.count - 1)
    }

    func verify(proof: Proof<H2G>) throws -> Bool {
        // Perform size checks on proof fields.
        if self.points.count != self.pointLabels.count {
            throw ZKPErrors.invalidProofFields
        }

        // For each constraint, recompute the blinded version of the constraint element.
        // Example: if the constraint is A=x*B, compute ABlind=challenge*A + xResponse*B
        // Example: if the constraint is A=x*B+y*C, compute ABlind=challenge*A + xResponse*B + yResponse*C
        var blindedPoints: [Group.Element] = []
        var blindedPointsLabels: [String] = []
        for (constraintPoint, linearCombination) in self.constraints {
            // Check that all PointVar and ScalarVar variables in the constraint have been correctly allocated.
            if !(0..<self.points.count).contains(constraintPoint.index) {
                throw ZKPErrors.invalidVariableAllocation
            }
            for (_, pointVar) in linearCombination {
                if !(0..<self.points.count).contains(pointVar.index) {
                    throw ZKPErrors.invalidVariableAllocation
                }
            }

            // challenge * constraintPoint
            let challengePoint = proof.challenge * self.points[constraintPoint.index]
            let blindedPoint = (linearCombination).map { (scalar, point) in
                proof.responses[scalar.index] * self.points[point.index]
            }.reduce(challengePoint, +)

            blindedPoints.append(blindedPoint)
            blindedPointsLabels.append(self.pointLabels[constraintPoint.index] + "-blind")
        }

        // Obtain a scalar challenge.
        let challenge = try Proof<H2G>.composeChallenge(label: self.label, points: self.points, pointLabels: self.pointLabels, blindedPoints: blindedPoints, blindedPointsLabels: blindedPointsLabels, scalarLabels: self.scalarLabels)

        return challenge == proof.challenge
    }
}


