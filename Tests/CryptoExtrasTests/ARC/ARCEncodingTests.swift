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
@testable import CryptoExtras
import XCTest
import Crypto

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
class ARCEncodingTests: XCTestCase {
    func serverPublicKeyEncoding<Curve: SupportedCurveDetailsImpl>(CurveType _: Curve.Type) throws {
        let ciphersuite = ARC.Ciphersuite(HashToCurveImpl<Curve>.self)
        let server = ARC.Server(ciphersuite: ciphersuite)
        let publicKey = server.serverPublicKey

        let publicKeyData = publicKey.serialize(ciphersuite: ciphersuite)
        let publicKey2 = try ARC.ServerPublicKey.deserialize(serverPublicKeyData: publicKeyData, ciphersuite: ciphersuite)
        XCTAssert(publicKey.X0 == publicKey2.X0)
        XCTAssert(publicKey.X1 == publicKey2.X1)
        XCTAssert(publicKey.X2 == publicKey2.X2)

        let publicKeyData2 = publicKey2.serialize(ciphersuite: ciphersuite)
        XCTAssertEqual(publicKeyData, publicKeyData2)
    }

    func testServerPublicKeyEncoding() throws {
        try serverPublicKeyEncoding(CurveType: P256.self)
        try serverPublicKeyEncoding(CurveType: P384.self)
    }

    func requestEncoding<Curve: SupportedCurveDetailsImpl>(CurveType _: Curve.Type) throws {
        let ciphersuite = ARC.Ciphersuite(HashToCurveImpl<Curve>.self)
        let server = ARC.Server(ciphersuite: ciphersuite)
        let requestContext = Data("test request context".utf8)
        let precredential = try ARC.Precredential(ciphersuite: ciphersuite, requestContext: requestContext, serverPublicKey: server.serverPublicKey)
        let request = precredential.credentialRequest

        let requestData = request.serialize(ciphersuite: ciphersuite)
        let request2 = try ARC.CredentialRequest.deserialize(requestData: requestData, ciphersuite: ciphersuite)
        XCTAssert(request.m1Enc == request2.m1Enc)
        XCTAssert(request.m2Enc == request2.m2Enc)
        XCTAssert(request.proof.challenge == request2.proof.challenge)
        for (index, response) in request.proof.responses.enumerated() {
            XCTAssert(response == request2.proof.responses[index])
        }

        let requestData2 = request2.serialize(ciphersuite: ciphersuite)
        XCTAssertEqual(requestData, requestData2)
    }

    func testRequestEncoding() throws {
        try requestEncoding(CurveType: P256.self)
        try requestEncoding(CurveType: P384.self)
    }

    func responseEncoding<Curve: SupportedCurveDetailsImpl>(CurveType _: Curve.Type) throws {
        let ciphersuite = ARC.Ciphersuite(HashToCurveImpl<Curve>.self)
        let server = ARC.Server(ciphersuite: ciphersuite)
        let requestContext = Data("test request context".utf8)
        let precredential = try ARC.Precredential(ciphersuite: ciphersuite, requestContext: requestContext, serverPublicKey: server.serverPublicKey)
        let request = precredential.credentialRequest
        let response = try server.respond(credentialRequest: request)

        let responseData = response.serialize(ciphersuite: ciphersuite)
        let response2 = try ARC.CredentialResponse.deserialize(responseData: responseData, ciphersuite: ciphersuite)
        XCTAssert(response.U == response2.U)
        XCTAssert(response.encUPrime == response2.encUPrime)
        XCTAssert(response.X0Aux == response2.X0Aux)
        XCTAssert(response.X1Aux == response2.X1Aux)
        XCTAssert(response.X2Aux == response2.X2Aux)
        XCTAssert(response.HAux == response2.HAux)
        XCTAssert(response.proof.challenge == response2.proof.challenge)
        for (index, response) in response.proof.responses.enumerated() {
            XCTAssert(response == response2.proof.responses[index])
        }

        let responseData2 = response2.serialize(ciphersuite: ciphersuite)
        XCTAssertEqual(responseData, responseData2)
    }

    func testResponseEncoding() throws {
        try responseEncoding(CurveType: P256.self)
        try responseEncoding(CurveType: P384.self)
    }

    func credentialEncoding<Curve: SupportedCurveDetailsImpl>(CurveType _: Curve.Type) throws {
        let ciphersuite = ARC.Ciphersuite(HashToCurveImpl<Curve>.self)
        let server = ARC.Server(ciphersuite: ciphersuite)
        let requestContext = Data("test request context".utf8)
        let precredential = try ARC.Precredential(ciphersuite: ciphersuite, requestContext: requestContext, serverPublicKey: server.serverPublicKey)
        let request = precredential.credentialRequest
        let response = try server.respond(credentialRequest: request)
        let credential = try precredential.makeCredential(credentialResponse: response)

        let credentialData = try credential.serialize(ciphersuite: ciphersuite)
        let credential2 = try ARC.Credential.deserialize(credentialData: credentialData, ciphersuite: ciphersuite)
        XCTAssert(credential.m1 == credential2.m1)
        XCTAssert(credential.U == credential2.U)
        XCTAssert(credential.UPrime == credential2.UPrime)
        XCTAssert(credential.X1 == credential2.X1)
        XCTAssert(credential.generatorG == credential2.generatorG)
        XCTAssert(credential.generatorH == credential2.generatorH)
        for (key, value) in credential.presentationState.state {
            XCTAssertEqual(value.0, credential2.presentationState.state[key]?.0)
            XCTAssertEqual(value.1, credential2.presentationState.state[key]?.1)
        }

        let credentialData2 = try credential2.serialize(ciphersuite: ciphersuite)
        XCTAssertEqual(credentialData, credentialData2)
    }

    func testCredentialEncoding() throws {
        try credentialEncoding(CurveType: P256.self)
        try credentialEncoding(CurveType: P384.self)
    }

    func presentationEncoding<Curve: SupportedCurveDetailsImpl>(CurveType _: Curve.Type) throws {
        let ciphersuite = ARC.Ciphersuite(HashToCurveImpl<Curve>.self)
        let server = ARC.Server(ciphersuite: ciphersuite)
        let requestContext = Data("test request context".utf8)
        let precredential = try ARC.Precredential(ciphersuite: ciphersuite, requestContext: requestContext, serverPublicKey: server.serverPublicKey)
        let request = precredential.credentialRequest
        let response = try server.respond(credentialRequest: request)
        var credential = try precredential.makeCredential(credentialResponse: response)
        let (presentation, _) = try credential.makePresentation(presentationContext: Data("test presentation context".utf8), presentationLimit: 1)

        let presentationData = presentation.serialize(ciphersuite: ciphersuite)
        let presentation2 = try ARC.Presentation.deserialize(presentationData: presentationData, ciphersuite: ciphersuite)
        XCTAssert(presentation.U == presentation2.U)
        XCTAssert(presentation.UPrimeCommit == presentation2.UPrimeCommit)
        XCTAssert(presentation.m1Commit == presentation2.m1Commit)
        XCTAssert(presentation.tag == presentation2.tag)
        XCTAssert(presentation.proof.challenge == presentation2.proof.challenge)
        for (index, response) in presentation.proof.responses.enumerated() {
            XCTAssert(response == presentation2.proof.responses[index])
        }

        let presentationData2 = presentation2.serialize(ciphersuite: ciphersuite)
        XCTAssertEqual(presentationData, presentationData2)
    }

    func testPresentationEncoding() throws {
        try presentationEncoding(CurveType: P256.self)
        try presentationEncoding(CurveType: P384.self)
    }

    func testPresentationStateEncoding() throws {
        let emptyPresentationState = ARC.PresentationState()
        let smallPresentationState = ARC.PresentationState(state: [Data("context1".utf8): (4, [1, 2, 3]), Data("context2".utf8): (10, [4, 5, 6])])
        var largePresentationState = ARC.PresentationState()
        for presentationLimit in 1..<100 {
            let presentationContext = Data("presentationContext\(presentationLimit)".utf8)
            for nonce in 0..<presentationLimit {
                let selectedNonce = try largePresentationState.update(presentationContext:presentationContext, presentationLimit: presentationLimit, optionalNonce: nonce)
                XCTAssertEqual(selectedNonce, nonce)
            }
        }

        for state in [emptyPresentationState, smallPresentationState, largePresentationState] {
            let serializedState = try state.serialize()
            XCTAssertNotNil(serializedState, "Serialized state should not be nil")

            let deserializedState = try ARC.PresentationState.deserialize(presentationStateData: serializedState)
            for (key, value) in state.state {
                XCTAssertEqual(value.0, deserializedState.state[key]?.0)
                XCTAssertEqual(value.1, deserializedState.state[key]?.1)
            }
        }
    }
}
