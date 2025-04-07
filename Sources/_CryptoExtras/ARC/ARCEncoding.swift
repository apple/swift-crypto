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
import Foundation
import Crypto

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias ARCCurve = P384
@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
typealias ARCH2G = HashToCurveImpl<ARCCurve>

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
extension ARC.CredentialRequest where H2G == ARCH2G {
    static let scalarCount = 5
    static let serializedByteCount = 2 * ARCCurve.compressedx962PointByteCount + Self.scalarCount * ARCCurve.orderByteCount

    func serialize() -> Data {
        var result = Data(capacity: Self.serializedByteCount)
        result.append(self.m1Enc.compressedRepresentation)
        result.append(self.m2Enc.compressedRepresentation)
        result.append(self.proof.serialize())
        return result
    }

    static func deserialize<D: DataProtocol>(requestData: D) throws -> ARC.CredentialRequest<ARCH2G> {
        guard requestData.count == Self.serializedByteCount else {
            throw ARC.Errors.incorrectRequestDataSize
        }

        var bytes = Data(requestData)

        let m1Enc = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ARCCurve.compressedx962PointByteCount))
        let m2Enc = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ARCCurve.compressedx962PointByteCount))
        let proof = try Proof.deserialize(proofData: bytes, scalarCount: Self.scalarCount)

        return ARC.CredentialRequest(m1Enc: m1Enc, m2Enc: m2Enc, proof: proof)
    }
}

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
extension ARC.CredentialResponse where H2G == ARCH2G {
    static let scalarCount = 8
    static let serializedByteCount = 6 * ARCCurve.compressedx962PointByteCount + Self.scalarCount * ARCCurve.orderByteCount

    func serialize() -> Data {
        var result = Data(capacity: Self.serializedByteCount)

        result.append(self.U.compressedRepresentation)
        result.append(self.encUPrime.compressedRepresentation)
        result.append(self.X0Aux.compressedRepresentation)
        result.append(self.X1Aux.compressedRepresentation)
        result.append(self.X2Aux.compressedRepresentation)
        result.append(self.HAux.compressedRepresentation)
        result.append(self.proof.serialize())

        return result
    }

    static func deserialize<D: DataProtocol>(responseData: D) throws -> ARC.CredentialResponse<ARCH2G> {
        guard responseData.count == self.serializedByteCount else {
            throw ARC.Errors.incorrectResponseDataSize
        }

        var bytes = Data(responseData)

        let U = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ARCCurve.compressedx962PointByteCount))
        let encUPrime = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ARCCurve.compressedx962PointByteCount))
        let X0Aux = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ARCCurve.compressedx962PointByteCount))
        let X1Aux = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ARCCurve.compressedx962PointByteCount))
        let X2Aux = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ARCCurve.compressedx962PointByteCount))
        let HAux = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ARCCurve.compressedx962PointByteCount))

        let proof = try Proof.deserialize(proofData: bytes, scalarCount: self.scalarCount)

        return ARC.CredentialResponse(U: U, encUPrime: encUPrime, X0Aux: X0Aux, X1Aux: X1Aux, X2Aux: X2Aux, HAux: HAux, proof: proof)
    }
}

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
extension ARC.Presentation where H2G == ARCH2G {
    static let scalarCount = 5
    static let pointCount = 4
    static let serializedByteCount = pointCount * ARCCurve.compressedx962PointByteCount + scalarCount * ARCCurve.orderByteCount

    func serialize() -> Data {
        var result = Data(capacity: Self.serializedByteCount)

        result.append(self.U.compressedRepresentation)
        result.append(self.UPrimeCommit.compressedRepresentation)
        result.append(self.m1Commit.compressedRepresentation)
        result.append(self.tag.compressedRepresentation)
        result.append(self.proof.serialize())

        return result
    }

    static func deserialize<D: DataProtocol>(presentationData: D) throws -> ARC.Presentation<ARCH2G> {
        guard presentationData.count == self.serializedByteCount else {
            throw ARC.Errors.incorrectPresentationDataSize
        }

        var bytes = Data(presentationData)

        let U = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ARCCurve.compressedx962PointByteCount))
        let UPrimeCommit = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ARCCurve.compressedx962PointByteCount))
        let m1Commit = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ARCCurve.compressedx962PointByteCount))
        let tag = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ARCCurve.compressedx962PointByteCount))
        let presentationProof = try Proof.deserialize(proofData: bytes, scalarCount: Self.scalarCount)

        return ARC.Presentation(U: U, UPrimeCommit: UPrimeCommit, m1Commit: m1Commit, tag: tag, proof: presentationProof)
    }
}

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
extension ARC.ServerPublicKey where H2G == ARCH2G {
    static let serializedByteCount = 3 * ARCCurve.compressedx962PointByteCount
    static let pointCount = 3  // TODO: delete

    func serialize() -> Data {
        var result = Data(capacity: Self.serializedByteCount)

        result.append(self.X0.compressedRepresentation)
        result.append(self.X1.compressedRepresentation)
        result.append(self.X2.compressedRepresentation)

        return result
    }

    static func deserialize<D: DataProtocol>(serverPublicKeyData: D) throws -> ARC.ServerPublicKey<ARCH2G> {
        guard serverPublicKeyData.count == self.pointCount * ARCCurve.compressedx962PointByteCount else {
            throw ARC.Errors.incorrectServerCommitmentsSize
        }

        var bytes = Data(serverPublicKeyData)

        let X0 = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ARCCurve.compressedx962PointByteCount))
        let X1 = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ARCCurve.compressedx962PointByteCount))
        let X2 = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ARCCurve.compressedx962PointByteCount))

        return ARC.ServerPublicKey(X0: X0, X1: X1, X2: X2)
    }
}

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
extension Proof where H2G == ARCH2G {
    func serialize() -> Data {
        let scalarCount = self.responses.count + 1
        var result = Data(capacity: scalarCount * ARCCurve.orderByteCount)

        // Serialize challenge
        result.append(self.challenge.rawRepresentation)
        // Serialize responses
        for response in self.responses {
            result.append(response.rawRepresentation)
        }
        return result
    }

    static func deserialize<D: DataProtocol>(proofData: D, scalarCount: Int) throws -> Proof<ARCH2G> {
        guard proofData.count == scalarCount * ARCCurve.orderByteCount else {
            throw ARC.Errors.incorrectProofDataSize
        }

        var bytes = Data(proofData)

        // Deserialize challenge
        let challenge = try ARCH2G.G.Scalar(bytes: bytes.popFirst(ARCCurve.orderByteCount))

        // Deserialize responses
        var responses: [GroupImpl<ARCCurve>.Scalar] = []
        responses.reserveCapacity(scalarCount - 1)
        for _ in (0..<scalarCount-1) {
            let response = try ARCH2G.G.Scalar(bytes: bytes.popFirst(ARCCurve.orderByteCount))
            responses.append(response)
        }

        return Proof(challenge: challenge, responses: responses)
    }
}

// Serialize a ARC credential, to save and restore client state.
// This will only be called client-side, and never be sent over the wire.
@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
extension ARC.Credential where H2G == ARCH2G {
    static let scalarCount = 1
    static let pointCount = 5

    static let serializedByteCountExcludingPresentationState = 1 * ARCCurve.orderByteCount + 5 * ARCCurve.compressedx962PointByteCount

    func serialize() throws -> Data {
        let presentationStateBytes = try self.presentationState.serialize()

        var result = Data(capacity: Self.serializedByteCountExcludingPresentationState + presentationStateBytes.count)

        result.append(self.m1.rawRepresentation)
        result.append(self.U.compressedRepresentation)
        result.append(self.UPrime.compressedRepresentation)
        result.append(self.X1.compressedRepresentation)
        result.append(self.generatorG.compressedRepresentation)
        result.append(self.generatorH.compressedRepresentation)
        result.append(presentationStateBytes)

        return result
    }

    static func deserialize<D: DataProtocol>(credentialData: D) throws -> ARC.Credential<ARCH2G> {
        guard credentialData.count - Self.serializedByteCountExcludingPresentationState >= 0 else {
            throw ARC.Errors.incorrectCredentialDataSize
        }
        let credentialData = Data(credentialData)

        var bytes = Data(credentialData)

        let m1 = try ARCH2G.G.Scalar(bytes: bytes.popFirst(ARCCurve.orderByteCount))
        let U = try ARCH2G.G.Element(oprfRepresentation: bytes.popFirst(ARCCurve.compressedx962PointByteCount))
        let UPrime = try ARCH2G.G.Element(oprfRepresentation: bytes.popFirst(ARCCurve.compressedx962PointByteCount))
        let X1 = try ARCH2G.G.Element(oprfRepresentation: bytes.popFirst(ARCCurve.compressedx962PointByteCount))
        let genG = try ARCH2G.G.Element(oprfRepresentation: bytes.popFirst(ARCCurve.compressedx962PointByteCount))
        let genH = try ARCH2G.G.Element(oprfRepresentation: bytes.popFirst(ARCCurve.compressedx962PointByteCount))

        // Deserialize presentationState from remaining bytes.
        let presentationState = try ARC.PresentationState.deserialize(presentationStateData: bytes)

        let ciphersuite = ARC.Ciphersuite(ARCH2G.self)
        return ARC.Credential(m1: m1, U: U, UPrime: UPrime, X1: X1, ciphersuite: ciphersuite, generatorG: genG, generatorH: genH, presentationState: presentationState)
    }
}

// Serialize a ARC PresentationState, to help save and restore a credential.
// This will only be called client-side, and never be sent over the wire.
@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
extension ARC.PresentationState {
    func serialize() throws -> Data {
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary

        // Convert (Int, Set<Int>) to Array<Int> for encoding
        let dictForEncoding = self.state.mapValues { [$0.0] + Array($0.1) }
        return try encoder.encode(dictForEncoding)
    }

    static func deserialize<D: DataProtocol>(presentationStateData: D) throws -> ARC.PresentationState {
        let decoder = PropertyListDecoder()

        let stateIntList = try decoder.decode([Data: [Int]].self, from: Data(presentationStateData))
        // Convert [Int] to (Int, Set<Int>) for decoding
        let state = stateIntList.mapValues { value in (value[0], Set(value[1...])) }

        return ARC.PresentationState(state: state)
    }
}
