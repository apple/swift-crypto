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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, *)
typealias ARCCurve = P384
@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, *)
typealias ARCH2G = HashToCurveImpl<ARCCurve>

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, *)
internal func DecodeInt(value: Data) -> Int {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, *)
    var result = Int(0)

    for i in 0..<value.count {
        result = result << 8
        result += Int(value[i])
    }

    return result
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, *)
internal func EncodeInt(value: Int) -> Data {
    return I2OSP(value: value, outputByteCount: 4)
}

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, *)
extension ARC.CredentialRequest where H2G == ARCH2G {
    static let scalarCount = 5
    static let pointCount = 2
    static let serializedByteCount = pointCount * ARCCurve.compressedx962PointByteCount + scalarCount * ARCCurve.orderByteCount

    func serialize() -> Data {
        let m1Enc = self.m1Enc.compressedRepresentation
        let m2Enc = self.m2Enc.compressedRepresentation
        let proofData = self.proof.serialize()
        return m1Enc + m2Enc + proofData
    }

    static func deserialize<D: DataProtocol>(requestData: D) throws -> ARC.CredentialRequest<ARCH2G> {
        guard requestData.count == self.serializedByteCount else {
            throw ARC.Errors.incorrectRequestDataSize
        }
        let requestData = Data(requestData)

        var startPointer = 0
        let m1Enc = try ARCH2G.G.Element(oprfRepresentation: requestData.subdata(in: startPointer..<startPointer+ARCCurve.compressedx962PointByteCount))
        startPointer += ARCCurve.compressedx962PointByteCount
        let m2Enc = try ARCH2G.G.Element(oprfRepresentation: requestData.subdata(in: startPointer..<startPointer+ARCCurve.compressedx962PointByteCount))
        startPointer += ARCCurve.compressedx962PointByteCount

        let proof = try Proof.deserialize(proofData: requestData.subdata(in: startPointer..<startPointer + self.scalarCount * ARCCurve.orderByteCount), scalarCount: self.scalarCount)
        return ARC.CredentialRequest(m1Enc: m1Enc, m2Enc: m2Enc, proof: proof)
    }
}

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, *)
extension ARC.CredentialResponse where H2G == ARCH2G {
    static let scalarCount = 8
    static let pointCount = 6
    static let serializedByteCount = pointCount * ARCCurve.compressedx962PointByteCount + scalarCount * ARCCurve.orderByteCount

    func serialize() -> Data {
        let U = self.U.compressedRepresentation
        let encUPrime = self.encUPrime.compressedRepresentation
        let X0Aux = self.X0Aux.compressedRepresentation
        let X1Aux = self.X1Aux.compressedRepresentation
        let X2Aux = self.X2Aux.compressedRepresentation
        let HAux = self.HAux.compressedRepresentation
        let responsePoints = U + encUPrime + X0Aux + X1Aux + X2Aux + HAux

        let proofData = self.proof.serialize()
        return responsePoints + proofData
    }

    static func deserialize<D: DataProtocol>(responseData: D) throws -> ARC.CredentialResponse<ARCH2G> {
        guard responseData.count == self.serializedByteCount else {
            throw ARC.Errors.incorrectResponseDataSize
        }
        let responseData = Data(responseData)

        var startPointer = 0
        let U = try ARCH2G.G.Element(oprfRepresentation: responseData.subdata(in: startPointer..<startPointer+ARCCurve.compressedx962PointByteCount))
        startPointer += ARCCurve.compressedx962PointByteCount
        let encUPrime = try ARCH2G.G.Element(oprfRepresentation: responseData.subdata(in: startPointer..<startPointer+ARCCurve.compressedx962PointByteCount))
        startPointer += ARCCurve.compressedx962PointByteCount
        let X0Aux = try ARCH2G.G.Element(oprfRepresentation: responseData.subdata(in: startPointer..<startPointer+ARCCurve.compressedx962PointByteCount))
        startPointer += ARCCurve.compressedx962PointByteCount
        let X1Aux = try ARCH2G.G.Element(oprfRepresentation: responseData.subdata(in: startPointer..<startPointer+ARCCurve.compressedx962PointByteCount))
        startPointer += ARCCurve.compressedx962PointByteCount
        let X2Aux = try ARCH2G.G.Element(oprfRepresentation: responseData.subdata(in: startPointer..<startPointer+ARCCurve.compressedx962PointByteCount))
        startPointer += ARCCurve.compressedx962PointByteCount
        let HAux = try ARCH2G.G.Element(oprfRepresentation: responseData.subdata(in: startPointer..<startPointer+ARCCurve.compressedx962PointByteCount))
        startPointer += ARCCurve.compressedx962PointByteCount

        let proof = try Proof.deserialize(proofData: responseData.subdata(in: startPointer..<startPointer + self.scalarCount * ARCCurve.orderByteCount), scalarCount: self.scalarCount)
        return ARC.CredentialResponse(U: U, encUPrime: encUPrime, X0Aux: X0Aux, X1Aux: X1Aux, X2Aux: X2Aux, HAux: HAux, proof: proof)
    }
}

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, *)
extension ARC.Presentation where H2G == ARCH2G {
    static let scalarCount = 5
    static let pointCount = 4
    static let serializedByteCount = pointCount * ARCCurve.compressedx962PointByteCount + scalarCount * ARCCurve.orderByteCount

    func serialize() -> Data {
        // Serialize presentation elements
        let U = self.U.compressedRepresentation
        let UPrimeCommit = self.UPrimeCommit.compressedRepresentation
        let m1Commit = self.m1Commit.compressedRepresentation
        let tag = self.tag.compressedRepresentation

        let presentationProofData = self.proof.serialize()
        return U + UPrimeCommit + m1Commit + tag + presentationProofData
    }

    static func deserialize<D: DataProtocol>(presentationData: D) throws -> ARC.Presentation<ARCH2G> {
        guard presentationData.count == self.serializedByteCount else {
            throw ARC.Errors.incorrectPresentationDataSize
        }
        let presentationData = Data(presentationData)

        var startPointer = 0
        // Deserialize presentation elements
        let U = try ARCH2G.G.Element(oprfRepresentation: presentationData.subdata(in: startPointer..<startPointer+ARCCurve.compressedx962PointByteCount))
        startPointer += ARCCurve.compressedx962PointByteCount
        let UPrimeCommit = try ARCH2G.G.Element(oprfRepresentation: presentationData.subdata(in: startPointer..<startPointer+ARCCurve.compressedx962PointByteCount))
        startPointer += ARCCurve.compressedx962PointByteCount
        let m1Commit = try ARCH2G.G.Element(oprfRepresentation: presentationData.subdata(in: startPointer..<startPointer+ARCCurve.compressedx962PointByteCount))
        startPointer += ARCCurve.compressedx962PointByteCount
        let tag = try ARCH2G.G.Element(oprfRepresentation: presentationData.subdata(in: startPointer..<startPointer+ARCCurve.compressedx962PointByteCount))
        startPointer += ARCCurve.compressedx962PointByteCount

        let presentationProof = try Proof.deserialize(proofData: presentationData.subdata(in: startPointer..<startPointer + self.scalarCount * ARCCurve.orderByteCount), scalarCount: self.scalarCount)
        return ARC.Presentation(U: U, UPrimeCommit: UPrimeCommit, m1Commit: m1Commit, tag: tag, proof: presentationProof)
    }
}

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, *)
extension ARC.ServerPublicKey where H2G == ARCH2G {
    static let pointCount = 3

    func serialize() -> Data {
        // Serialize server commitment elements
        let X0 = self.X0.compressedRepresentation
        let X1 = self.X1.compressedRepresentation
        let X2 = self.X2.compressedRepresentation

        return X0 + X1 + X2
    }

    static func deserialize<D: DataProtocol>(serverPublicKeyData: D) throws -> ARC.ServerPublicKey<ARCH2G> {
        guard serverPublicKeyData.count == self.pointCount * ARCCurve.compressedx962PointByteCount else {
            throw ARC.Errors.incorrectServerCommitmentsSize
        }
        let serverPublicKeyData = Data(serverPublicKeyData)
        var startPointer = 0

        // Deserialize server commitment elements
        let X0 = try ARCH2G.G.Element(oprfRepresentation: serverPublicKeyData.subdata(in: startPointer..<startPointer+ARCCurve.compressedx962PointByteCount))
        startPointer += ARCCurve.compressedx962PointByteCount
        let X1 = try ARCH2G.G.Element(oprfRepresentation: serverPublicKeyData.subdata(in: startPointer..<startPointer+ARCCurve.compressedx962PointByteCount))
        startPointer += ARCCurve.compressedx962PointByteCount
        let X2 = try ARCH2G.G.Element(oprfRepresentation: serverPublicKeyData.subdata(in: startPointer..<startPointer+ARCCurve.compressedx962PointByteCount))
        startPointer += ARCCurve.compressedx962PointByteCount

        return ARC.ServerPublicKey(X0: X0, X1: X1, X2: X2)
    }
}

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, *)
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
        let proofData = Data(proofData)
        var startPointer = 0

        // Deserialize challenge
        let challenge = try GroupImpl<ARCCurve>.Scalar(bytes: proofData.subdata(in: startPointer..<startPointer+ARCCurve.orderByteCount))
        startPointer += ARCCurve.orderByteCount

        // Deserialize responses
        var responses: [GroupImpl<ARCCurve>.Scalar] = []
        for _ in (0..<scalarCount-1) {
            let response = try GroupImpl<ARCCurve>.Scalar(bytes: proofData.subdata(in: startPointer..<startPointer+ARCCurve.orderByteCount))
            responses.append(response)
            startPointer += ARCCurve.orderByteCount
        }

        return Proof(challenge: challenge, responses: responses)
    }
}

// Serialize a ARC credential, to save and restore client state.
// This will only be called client-side, and never be sent over the wire.
@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, *)
extension ARC.Credential where H2G == ARCH2G {
    static let scalarCount = 1
    static let pointCount = 5
    static let integerByteCount = 4

    func serialize() throws -> Data {
        let m1 = self.m1.rawRepresentation
        let U = self.U.compressedRepresentation
        let UPrime = self.UPrime.compressedRepresentation
        let X1 = self.X1.compressedRepresentation
        let genG = self.generatorG.compressedRepresentation
        let genH = self.generatorH.compressedRepresentation
        let presentationLimit = EncodeInt(value: self.presentationLimit)
        let noncesData = try ARCNonces.serialize(noncesDict: self.presentationNonces)

        return m1 + U + UPrime + X1 + genG + genH + presentationLimit + noncesData
    }

    static func deserialize<D: DataProtocol>(credentialData: D) throws -> ARC.Credential<ARCH2G> {
        let noncesByteCount = credentialData.count - self.scalarCount *  ARCCurve.orderByteCount - self.pointCount * ARCCurve.compressedx962PointByteCount - integerByteCount
        guard noncesByteCount >= 0 else {
            throw ARC.Errors.incorrectCredentialDataSize
        }
        let credentialData = Data(credentialData)

        var startPointer = 0
        let m1 = try GroupImpl<ARCCurve>.Scalar(bytes: credentialData.subdata(in: startPointer..<startPointer+ARCCurve.orderByteCount))
        startPointer += ARCCurve.orderByteCount
        let U = try ARCH2G.G.Element(oprfRepresentation: credentialData.subdata(in: startPointer..<startPointer+ARCCurve.compressedx962PointByteCount))
        startPointer += ARCCurve.compressedx962PointByteCount
        let UPrime = try ARCH2G.G.Element(oprfRepresentation: credentialData.subdata(in: startPointer..<startPointer+ARCCurve.compressedx962PointByteCount))
        startPointer += ARCCurve.compressedx962PointByteCount
        let X1 = try ARCH2G.G.Element(oprfRepresentation: credentialData.subdata(in: startPointer..<startPointer+ARCCurve.compressedx962PointByteCount))
        startPointer += ARCCurve.compressedx962PointByteCount
        let genG = try ARCH2G.G.Element(oprfRepresentation: credentialData.subdata(in: startPointer..<startPointer+ARCCurve.compressedx962PointByteCount))
        startPointer += ARCCurve.compressedx962PointByteCount
        let genH = try ARCH2G.G.Element(oprfRepresentation: credentialData.subdata(in: startPointer..<startPointer+ARCCurve.compressedx962PointByteCount))
        startPointer += ARCCurve.compressedx962PointByteCount
        let presentationLimit = DecodeInt(value: credentialData.subdata(in: startPointer..<startPointer+self.integerByteCount))
        startPointer += self.integerByteCount

        // Deserialize presentationNonces dictionary
        let noncesData = credentialData.subdata(in: startPointer..<startPointer+noncesByteCount)
        let presentationNonces = try ARCNonces.deserialize(noncesData: noncesData)

        let ciphersuite = ARC.Ciphersuite(ARCH2G.self)
        return ARC.Credential(m1: m1, U: U, UPrime: UPrime, X1: X1, presentationLimit: presentationLimit, presentationNonces: presentationNonces, ciphersuite: ciphersuite, generatorG: genG, generatorH: genH)
    }
}

// A helper for serializing a ARC credential. This will only be called client-side, and never be sent over the wire.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, *)
struct ARCNonces {
    static func serialize(noncesDict: [Data: Set<Int>]) throws -> Data {
        // Convert Set<Int> to Array<Int> for encoding
        let dictForEncoding = noncesDict.mapValues {Array($0) }
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        return try encoder.encode(dictForEncoding)
    }

    static func deserialize<D: DataProtocol>(noncesData: D) throws -> [Data: Set<Int>] {
        let decoder = PropertyListDecoder()
        // Decode as [Data: [Int]] and convert Array<Int> back to Set<Int>
        let decodedDictionary = try decoder.decode([Data: [Int]].self, from: Data(noncesData))
        return decodedDictionary.mapValues { Set($0) }
    }
}
