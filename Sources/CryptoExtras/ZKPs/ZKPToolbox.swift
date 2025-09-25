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
struct ScalarVar {
    var index: Int
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct PointVar {
    var index: Int
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
enum ZKPErrors: Error {
    case invalidVariableAllocation
    case invalidInputLength
    case invalidProofFields
}

// A Schnorr proof, which stores the challenge instead of 
// commitments to the prover's randomness (blindedPoints).
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct Proof<H2G: HashToGroup> {
    typealias Group = H2G.G
    public let challenge: Group.Scalar
    public let responses: [Group.Scalar]

    static func composeChallenge(label: String, points: [Group.Element], pointLabels: [String], blindedPoints: [Group.Element], blindedPointsLabels: [String], scalarLabels: [String]) throws -> Group.Scalar {
        var challengeInput = Data()

        // Pass the public points into the transcript.
        for point in points {
            let serializedPoint = point.oprfRepresentation
            challengeInput.append(I2OSP(value: serializedPoint.count, outputByteCount: 2) + serializedPoint)
        }

        // Pass the computed blinded points into the transcript.
        for point in blindedPoints {
            let serializedPoint = point.oprfRepresentation
            challengeInput.append(I2OSP(value: serializedPoint.count, outputByteCount: 2) + serializedPoint)
        }

        // Get the challenge output from the transcript.
        return try H2G.hashToScalar(challengeInput, domainSeparationString: Data(label.utf8))
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
protocol ProofParticipant {
    associatedtype Point: GroupElement
    var label: String { get }
    var scalarLabels: [String] { get set }
    var points: [Point] { get set }
    var pointLabels: [String] { get set }
    var constraints: [(PointVar, [(ScalarVar, PointVar)])] { get set }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ProofParticipant {
    mutating func constrain(result: PointVar, linearCombination: [(ScalarVar, PointVar)]) {
        self.constraints.append((result, linearCombination))
    }

    mutating func appendPoint(label: String, assignment: any GroupElement) -> PointVar {
        self.pointLabels.append(label)
        self.points.append(assignment as! Self.Point)
        return PointVar(index: self.points.count - 1)
    }
}
