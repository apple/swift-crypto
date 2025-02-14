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
@testable import _CryptoExtras
import XCTest
import Crypto

class ARCEncodingTests: XCTestCase {
    func testserverPublicKeyEncoding() throws {
        let ciphersuite = ARC.Ciphersuite(HashToCurveImpl<ARCCurve>.self)
        let server = ARC.Server(ciphersuite: ciphersuite)
        let publicKey = server.serverPublicKey

        let publicKeyData = publicKey.serialize()
        let publicKey2 = try ARC.ServerPublicKey.deserialize(serverPublicKeyData: publicKeyData)
        XCTAssert(publicKey.X0 == publicKey2.X0)
        XCTAssert(publicKey.X1 == publicKey2.X1)
        XCTAssert(publicKey.X2 == publicKey2.X2)

        let publicKeyData2 = publicKey2.serialize()
        XCTAssertEqual(publicKeyData, publicKeyData2)
    }

    func testRequestEncoding() throws {
        let ciphersuite = ARC.Ciphersuite(HashToCurveImpl<ARCCurve>.self)
        let server = ARC.Server(ciphersuite: ciphersuite)
        let requestContext = Data("test request context".utf8)
        let precredential = try ARC.Precredential(ciphersuite: ciphersuite, requestContext: requestContext, serverPublicKey: server.serverPublicKey, presentationLimit: 1)
        let request = precredential.credentialRequest

        let requestData = request.serialize()
        let request2 = try ARC.CredentialRequest.deserialize(requestData: requestData)
        XCTAssert(request.m1Enc == request2.m1Enc)
        XCTAssert(request.m2Enc == request2.m2Enc)
        XCTAssert(request.proof.challenge == request2.proof.challenge)
        for (index, response) in request.proof.responses.enumerated() {
            XCTAssert(response == request2.proof.responses[index])
        }

        let requestData2 = request2.serialize()
        XCTAssertEqual(requestData, requestData2)
    }

    func testResponseEncoding() throws {
        let ciphersuite = ARC.Ciphersuite(HashToCurveImpl<ARCCurve>.self)
        let server = ARC.Server(ciphersuite: ciphersuite)
        let requestContext = Data("test request context".utf8)
        let precredential = try ARC.Precredential(ciphersuite: ciphersuite, requestContext: requestContext, serverPublicKey: server.serverPublicKey, presentationLimit: 1)
        let request = precredential.credentialRequest
        let response = try server.respond(credentialRequest: request)

        let responseData = response.serialize()
        let response2 = try ARC.CredentialResponse.deserialize(responseData: responseData)
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

        let responseData2 = response2.serialize()
        XCTAssertEqual(responseData, responseData2)
    }

    func testCredentialEncoding() throws {
        let ciphersuite = ARC.Ciphersuite(HashToCurveImpl<ARCCurve>.self)
        let server = ARC.Server(ciphersuite: ciphersuite)
        let requestContext = Data("test request context".utf8)
        let precredential = try ARC.Precredential(ciphersuite: ciphersuite, requestContext: requestContext, serverPublicKey: server.serverPublicKey, presentationLimit: 1)
        let request = precredential.credentialRequest
        let response = try server.respond(credentialRequest: request)
        let credential = try precredential.makeCredential(credentialResponse: response)

        let credentialData = try credential.serialize()
        let credential2 = try ARC.Credential.deserialize(credentialData: credentialData)
        XCTAssert(credential.m1 == credential2.m1)
        XCTAssert(credential.U == credential2.U)
        XCTAssert(credential.UPrime == credential2.UPrime)
        XCTAssert(credential.X1 == credential2.X1)
        XCTAssert(credential.generatorG == credential2.generatorG)
        XCTAssert(credential.generatorH == credential2.generatorH)
        XCTAssert(credential.presentationLimit == credential2.presentationLimit)
        XCTAssert(credential.presentationNonces == credential2.presentationNonces)

        let credentialData2 = try credential2.serialize()
        XCTAssertEqual(credentialData, credentialData2)
    }

    func testPresentationEncoding() throws {
        let ciphersuite = ARC.Ciphersuite(HashToCurveImpl<ARCCurve>.self)
        let server = ARC.Server(ciphersuite: ciphersuite)
        let requestContext = Data("test request context".utf8)
        let precredential = try ARC.Precredential(ciphersuite: ciphersuite, requestContext: requestContext, serverPublicKey: server.serverPublicKey, presentationLimit: 1)
        let request = precredential.credentialRequest
        let response = try server.respond(credentialRequest: request)
        var credential = try precredential.makeCredential(credentialResponse: response)
        let (presentation, _) = try credential.makePresentation(presentationContext: Data("test presentation context".utf8))

        let presentationData = presentation.serialize()
        let presentation2 = try ARC.Presentation.deserialize(presentationData: presentationData)
        XCTAssert(presentation.U == presentation2.U)
        XCTAssert(presentation.UPrimeCommit == presentation2.UPrimeCommit)
        XCTAssert(presentation.m1Commit == presentation2.m1Commit)
        XCTAssert(presentation.tag == presentation2.tag)
        XCTAssert(presentation.proof.challenge == presentation2.proof.challenge)
        for (index, response) in presentation.proof.responses.enumerated() {
            XCTAssert(response == presentation2.proof.responses[index])
        }

        let presentationData2 = presentation2.serialize()
        XCTAssertEqual(presentationData, presentationData2)
    }

    func testDictionaryEncoding() throws {
        let emptyDictionary: [Data: Set<Int>] = [:]
        let smallDictionary: [Data: Set<Int>] = [Data("context1".utf8): [1, 2, 3], Data("context2".utf8): [4, 5, 6]]
        var largeDictionary: [Data: Set<Int>] = [:]
        for i in 0..<1000 {
            let key = Data("key\(i)".utf8)
            let value = Set(0...1000)
            largeDictionary[key] = value
        }

        for dictionary in [emptyDictionary, smallDictionary, largeDictionary] {
            let serializedDictionary = try ARCNonces.serialize(noncesDict: dictionary)
            XCTAssertNotNil(serializedDictionary, "Serialized data should not be nil")
            let deserializedDictionary = try ARCNonces.deserialize(noncesData: serializedDictionary)
            XCTAssertEqual(dictionary, deserializedDictionary, "Deserialized dictionary should match the original")
        }
    }
}
