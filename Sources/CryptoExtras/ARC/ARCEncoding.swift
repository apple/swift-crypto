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

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
typealias ARCP256 = HashToCurveImpl<P256>
@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
typealias ARCP384 = HashToCurveImpl<P384>

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
extension ARC.CredentialRequest {
    static func getScalarCount() -> Int { return 5 }
    static func getSerializedByteCount(_ ciphersuite: ARC.Ciphersuite<H2G>) -> Int {
        return 2 * ciphersuite.pointByteCount + Self.getScalarCount() * ciphersuite.scalarByteCount
    }

    func serialize(ciphersuite: ARC.Ciphersuite<H2G>) -> Data {
        var result = Data(capacity: Self.getSerializedByteCount(ciphersuite))
        result.append(self.m1Enc.oprfRepresentation)
        result.append(self.m2Enc.oprfRepresentation)
        result.append(self.proof.serialize(ciphersuite: ciphersuite))
        return result
    }

    static func deserialize<D: DataProtocol>(requestData: D, ciphersuite: ARC.Ciphersuite<H2G>) throws -> ARC.CredentialRequest<H2G> {
        guard requestData.count == Self.getSerializedByteCount(ciphersuite) else {
            throw ARC.Errors.incorrectRequestDataSize
        }

        var bytes = Data(requestData)

        let m1Enc = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ciphersuite.pointByteCount))
        let m2Enc = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ciphersuite.pointByteCount))
        let proof = try Proof<H2G>.deserialize(proofData: bytes, scalarCount: Self.getScalarCount(), ciphersuite: ciphersuite)

        return ARC.CredentialRequest(m1Enc: m1Enc, m2Enc: m2Enc, proof: proof)
    }
}

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
extension ARC.CredentialResponse {
    static func getScalarCount() -> Int { return 8 }
    static func getSerializedByteCount(_ ciphersuite: ARC.Ciphersuite<H2G>) -> Int {
        return 6 * ciphersuite.pointByteCount + Self.getScalarCount() * ciphersuite.scalarByteCount
    }

    func serialize(ciphersuite: ARC.Ciphersuite<H2G>) -> Data {
        var result = Data(capacity: Self.getSerializedByteCount(ciphersuite))

        result.append(self.U.oprfRepresentation)
        result.append(self.encUPrime.oprfRepresentation)
        result.append(self.X0Aux.oprfRepresentation)
        result.append(self.X1Aux.oprfRepresentation)
        result.append(self.X2Aux.oprfRepresentation)
        result.append(self.HAux.oprfRepresentation)
        result.append(self.proof.serialize(ciphersuite: ciphersuite))

        return result
    }

    static func deserialize<D: DataProtocol>(responseData: D, ciphersuite: ARC.Ciphersuite<H2G>) throws -> ARC.CredentialResponse<H2G> {
        guard responseData.count == self.getSerializedByteCount(ciphersuite) else {
            throw ARC.Errors.incorrectResponseDataSize
        }

        var bytes = Data(responseData)

        let U = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ciphersuite.pointByteCount))
        let encUPrime = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ciphersuite.pointByteCount))
        let X0Aux = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ciphersuite.pointByteCount))
        let X1Aux = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ciphersuite.pointByteCount))
        let X2Aux = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ciphersuite.pointByteCount))
        let HAux = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ciphersuite.pointByteCount))

        let proof = try Proof<H2G>.deserialize(proofData: bytes, scalarCount: Self.getScalarCount(), ciphersuite: ciphersuite)

        return ARC.CredentialResponse(U: U, encUPrime: encUPrime, X0Aux: X0Aux, X1Aux: X1Aux, X2Aux: X2Aux, HAux: HAux, proof: proof)
    }
}

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
extension ARC.Presentation {
    static func getScalarCount() -> Int { return 5 }
    static func getPointCount() -> Int { return 4 }
    static func getSerializedByteCount(_ ciphersuite: ARC.Ciphersuite<H2G>) -> Int {
        return Self.getPointCount() * ciphersuite.pointByteCount + Self.getScalarCount() * ciphersuite.scalarByteCount
    }

    func serialize(ciphersuite: ARC.Ciphersuite<H2G>) -> Data {
        var result = Data(capacity: Self.getSerializedByteCount(ciphersuite))

        result.append(self.U.oprfRepresentation)
        result.append(self.UPrimeCommit.oprfRepresentation)
        result.append(self.m1Commit.oprfRepresentation)
        result.append(self.tag.oprfRepresentation)
        result.append(self.proof.serialize(ciphersuite: ciphersuite))

        return result
    }

    static func deserialize<D: DataProtocol>(presentationData: D, ciphersuite: ARC.Ciphersuite<H2G>) throws -> ARC.Presentation<H2G> {
        guard presentationData.count == self.getSerializedByteCount(ciphersuite) else {
            throw ARC.Errors.incorrectPresentationDataSize
        }

        var bytes = Data(presentationData)

        let U = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ciphersuite.pointByteCount))
        let UPrimeCommit = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ciphersuite.pointByteCount))
        let m1Commit = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ciphersuite.pointByteCount))
        let tag = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ciphersuite.pointByteCount))
        let presentationProof = try Proof<H2G>.deserialize(proofData: bytes, scalarCount: Self.getScalarCount(), ciphersuite: ciphersuite)

        return ARC.Presentation(U: U, UPrimeCommit: UPrimeCommit, m1Commit: m1Commit, tag: tag, proof: presentationProof)
    }
}

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
extension ARC.ServerPublicKey {
    static func getSerializedByteCount(_ ciphersuite: ARC.Ciphersuite<H2G>) -> Int {
        return 3 * ciphersuite.pointByteCount
    }

    func serialize(ciphersuite: ARC.Ciphersuite<H2G>) -> Data {
        var result = Data(capacity: Self.getSerializedByteCount(ciphersuite))

        result.append(self.X0.oprfRepresentation)
        result.append(self.X1.oprfRepresentation)
        result.append(self.X2.oprfRepresentation)

        return result
    }

    static func deserialize<D: DataProtocol>(serverPublicKeyData: D, ciphersuite: ARC.Ciphersuite<H2G>) throws -> ARC.ServerPublicKey<H2G> {
        guard serverPublicKeyData.count == self.getSerializedByteCount(ciphersuite) else {
            throw ARC.Errors.incorrectServerCommitmentsSize
        }

        var bytes = Data(serverPublicKeyData)

        let X0 = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ciphersuite.pointByteCount))
        let X1 = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ciphersuite.pointByteCount))
        let X2 = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ciphersuite.pointByteCount))

        return ARC.ServerPublicKey(X0: X0, X1: X1, X2: X2)
    }
}

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
extension Proof {
    func serialize(ciphersuite: ARC.Ciphersuite<H2G>) -> Data {
        let scalarCount = self.responses.count + 1
        var result = Data(capacity: scalarCount * ciphersuite.scalarByteCount)

        // Serialize challenge
        result.append(self.challenge.rawRepresentation)
        // Serialize responses
        for response in self.responses {
            result.append(response.rawRepresentation)
        }
        return result
    }

    static func deserialize<D: DataProtocol>(proofData: D, scalarCount: Int, ciphersuite: ARC.Ciphersuite<H2G>) throws -> Proof<H2G> {
        guard proofData.count == scalarCount * ciphersuite.scalarByteCount else {
            throw ARC.Errors.incorrectProofDataSize
        }

        var bytes = Data(proofData)

        // Deserialize challenge
        let challenge = try H2G.G.Scalar(bytes: bytes.popFirst(ciphersuite.scalarByteCount), reductionIsModOrder: true)

        // Deserialize responses
        var responses: [H2G.G.Scalar] = []
        responses.reserveCapacity(scalarCount - 1)
        for _ in (0..<scalarCount-1) {
            let response = try H2G.G.Scalar(bytes: bytes.popFirst(ciphersuite.scalarByteCount), reductionIsModOrder: true)
            responses.append(response)
        }

        return Proof(challenge: challenge, responses: responses)
    }
}

// Serialize a ARC credential, to save and restore client state.
// This will only be called client-side, and never be sent over the wire.
@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
extension ARC.Credential {
    static func getScalarCount() -> Int { return 1 }
    static func getPointCount() -> Int { return 5 }
    static func getSerializedByteCountExcludingPresentationState(_ ciphersuite: ARC.Ciphersuite<H2G>) -> Int {
        return Self.getPointCount() * ciphersuite.pointByteCount + Self.getScalarCount() * ciphersuite.scalarByteCount
    }

    func serialize(ciphersuite: ARC.Ciphersuite<H2G>) throws -> Data {
        let presentationStateBytes = try self.presentationState.serialize()
        var result = Data(capacity: Self.getSerializedByteCountExcludingPresentationState(ciphersuite) + presentationStateBytes.count)

        result.append(self.m1.rawRepresentation)
        result.append(self.U.oprfRepresentation)
        result.append(self.UPrime.oprfRepresentation)
        result.append(self.X1.oprfRepresentation)
        result.append(self.generatorG.oprfRepresentation)
        result.append(self.generatorH.oprfRepresentation)
        result.append(presentationStateBytes)

        return result
    }

    static func deserialize<D: DataProtocol>(credentialData: D, ciphersuite: ARC.Ciphersuite<H2G>) throws -> ARC.Credential<H2G> {
        guard credentialData.count - Self.getSerializedByteCountExcludingPresentationState(ciphersuite) >= 0 else {
            throw ARC.Errors.incorrectCredentialDataSize
        }
        let credentialData = Data(credentialData)

        var bytes = Data(credentialData)

        let m1 = try H2G.G.Scalar(bytes: bytes.popFirst(ciphersuite.scalarByteCount), reductionIsModOrder: true)
        let U = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ciphersuite.pointByteCount))
        let UPrime = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ciphersuite.pointByteCount))
        let X1 = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ciphersuite.pointByteCount))
        let genG = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ciphersuite.pointByteCount))
        let genH = try H2G.G.Element(oprfRepresentation: bytes.popFirst(ciphersuite.pointByteCount))

        // Deserialize presentationState from remaining bytes.
        let presentationState = try ARC.PresentationState.deserialize(presentationStateData: bytes)

        let ciphersuite = ARC.Ciphersuite(H2G.self)
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
