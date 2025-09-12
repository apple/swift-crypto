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
class ARCTests: XCTestCase {
    func endToEndWorkflow<Curve: SupportedCurveDetailsImpl>(CurveType _: Curve.Type) throws {
        let ciphersuite = ARC.Ciphersuite(HashToCurveImpl<Curve>.self)
        let (generatorG, generatorH) = ARC.getGenerators(suite: ciphersuite)

        // Create a server, passing in the server keys and key blinding.
        let x0 = GroupImpl<Curve>.Scalar.random
        let x1 = GroupImpl<Curve>.Scalar.random
        let x2 = GroupImpl<Curve>.Scalar.random
        let x0Blinding = GroupImpl<Curve>.Scalar.random
        let serverPrivateKey = ARC.ServerPrivateKey(x0: x0, x1: x1, x2: x2, x0Blinding: x0Blinding)
        let server = ARC.Server(ciphersuite: ciphersuite, x0: x0, x1: x1, x2: x2, x0Blinding: x0Blinding)
        let serverPublicKey = server.serverPublicKey
        XCTAssert(serverPublicKey.X0 == x0 * generatorG + x0Blinding * generatorH)
        XCTAssert(serverPublicKey.X1 == x1 * generatorH)
        XCTAssert(serverPublicKey.X2 == x2 * generatorH)

        // Create a client with two private attributes.
        let presentationLimit = 2
        let requestContext = Data("test request context".utf8)
        let m1 = GroupImpl<Curve>.Scalar.random
        let r1 = GroupImpl<Curve>.Scalar.random
        let r2 = GroupImpl<Curve>.Scalar.random
        let precredential = try ARC.Precredential(ciphersuite: ciphersuite, m1: m1, requestContext: requestContext, r1: r1, r2: r2, serverPublicKey: serverPublicKey)

        // Client makes an CredentialRequest using its private attributes.
        let request = precredential.credentialRequest
        let m1Decrypted = request.m1Enc - r1 * generatorH
        XCTAssert(m1Decrypted == m1 * generatorG)
        let m2Decrypted = request.m2Enc - r2 * generatorH
        XCTAssert(m2Decrypted == precredential.clientSecrets.m2 * generatorG)
        XCTAssert(try request.verify(generatorG: generatorG, generatorH: generatorH, ciphersuite: ciphersuite))

        // Server receives the CredentialRequest, and makes an CredentialResponse with its server keys.
        let issuance = try server.respond(credentialRequest: request)
        let decryptedUPrime = issuance.encUPrime - issuance.X0Aux - r1 * issuance.X1Aux - r2 * issuance.X2Aux
        XCTAssert(decryptedUPrime == (x0 + m1 * x1 + precredential.clientSecrets.m2 * x2) * issuance.U)

        // Client receives the CredentialResponse, and uses it to make a credential from the precredential.
        var credential = try precredential.makeCredential(credentialResponse: issuance)
        XCTAssertNotNil(credential)

        // Client makes two Presentations from the Credential.
        // Note that in practice, the definition of presentationContext would depend on the use case of the tag (e.g. rate limiting).
        let presentationContext = Data("0123456789".utf8)
        let (presentation1, nonce1) = try credential.makePresentation(presentationContext: presentationContext, presentationLimit: presentationLimit)
        let (presentation2, nonce2) = try credential.makePresentation(presentationContext: presentationContext, presentationLimit: presentationLimit)
        XCTAssertNotNil(presentation1)
        XCTAssertNotNil(presentation2)

        // We hit the limit for the presentationContext, and should not receive any new presentations
        XCTAssertThrowsError(try credential.makePresentation(presentationContext: presentationContext, presentationLimit: presentationLimit), error: ARC.Errors.presentationLimitExceeded)
        // But we can make more presentations under a different presentationContext
        let newPresentationContext = Data("ABCDEF".utf8)
        let (presentation3, nonce3) = try credential.makePresentation(presentationContext: newPresentationContext, presentationLimit: presentationLimit)
        XCTAssertNotNil(presentation3)

        // Server verifies Presentation1 with its server keys.
        XCTAssert(try server.verify(presentation: presentation1, requestContext: requestContext, presentationContext: presentationContext, presentationLimit: presentationLimit, nonce: nonce1))
        // Verify presentation individually
        XCTAssert(try presentation1.verify(
            serverPrivateKey: serverPrivateKey,
            X1: x1 * generatorH,
            m2: precredential.clientSecrets.m2,
            presentationContext: presentationContext,
            presentationLimit: presentationLimit,
            nonce: nonce1,
            generatorG: generatorG,
            generatorH: generatorH,
            ciphersuite: ciphersuite))

        // Server verifies Presentation2 with its server keys.
        XCTAssert(try server.verify(
            presentation: presentation2,
            requestContext: requestContext,
            presentationContext: presentationContext,
            presentationLimit: presentationLimit,
            nonce: nonce2))
        // Verify presentation individually
        XCTAssert(try presentation2.verify(
            serverPrivateKey: serverPrivateKey,
            X1: x1 * generatorH,
            m2: precredential.clientSecrets.m2,
            presentationContext: presentationContext,
            presentationLimit: presentationLimit,
            nonce: nonce2,
            generatorG: generatorG,
            generatorH: generatorH,
            ciphersuite: ciphersuite))

        // Test that two presentations with the same presentationContext and privateAttribute,
        // but difference nonces, have different tag elements
        XCTAssertNotEqual(presentation1.tag.compressedRepresentation, presentation2.tag.compressedRepresentation)

        // Server verifies Presentation3 with its server keys.
        XCTAssert(try server.verify(presentation: presentation3, requestContext: requestContext, presentationContext: newPresentationContext, presentationLimit: presentationLimit, nonce: nonce3))

        // Test that verifying Presentation3 with the wrong presentationContext fails.
        XCTAssertFalse(try server.verify(
            presentation: presentation3,
            requestContext: requestContext,
            presentationContext: presentationContext,
            presentationLimit: presentationLimit,
            nonce: nonce3))
        // Test that verifying Presentation3 with an invalid presentationLimit fails.
        XCTAssertFalse(try server.verify(
            presentation: presentation3,
            requestContext: requestContext,
            presentationContext: newPresentationContext,
            presentationLimit: 0,
            nonce: nonce3))
        // Test that verifying Presentation1 with the wrong nonce fails.
        XCTAssertFalse(try server.verify(
            presentation: presentation1,
            requestContext: requestContext,
            presentationContext: newPresentationContext,
            presentationLimit: presentationLimit,
            nonce: nonce2))
        // Test that verifying Presentation1 with the wrong request context fails.
        XCTAssertFalse(try server.verify(
            presentation: presentation1,
            requestContext: Data("wrong request context".utf8),
            presentationContext: newPresentationContext,
            presentationLimit: presentationLimit,
            nonce: nonce1))

        // Test that verifying with the wrong server (wrong server keys) fails.
        let wrongServer = ARC.Server(ciphersuite: ciphersuite)
        XCTAssertFalse(try wrongServer.verify(
            presentation: presentation3,
            requestContext: requestContext,
            presentationContext: presentationContext,
            presentationLimit: presentationLimit,
            nonce: nonce3))
    }

    func testEndToEndWorkflow() throws {
        try endToEndWorkflow(CurveType: P256.self)
        try endToEndWorkflow(CurveType: P384.self)
//        try endToEndWorkflow(CurveType: P521.self)
    }

    func testPresentationState() throws {
        let context1 = Data("context1".utf8)
        let context2 = Data("context2".utf8)
        var smallPresentationState = ARC.PresentationState(state: [context1: (4, [0, 1, 2]), context2: (10, [3, 4, 5, 6])])

        // Test that a new nonce is selected correctly
        XCTAssertEqual(3, try smallPresentationState.update(presentationContext: context1, presentationLimit: 4))
        XCTAssertEqual(0, try smallPresentationState.update(presentationContext: Data("context 3".utf8), presentationLimit: 1))
        XCTAssert(try smallPresentationState.update(presentationContext: context2, presentationLimit: 10) < 10)
        // Test that exceeding the rate limit for a presentationContext throws an error
        XCTAssertThrowsError(try smallPresentationState.update(presentationContext: context1, presentationLimit: 4), error: ARC.Errors.presentationLimitExceeded)
        // Test that reusing a nonce for a presentationContext throws an error
        XCTAssertThrowsError(try smallPresentationState.update(presentationContext: context2, presentationLimit: 10, optionalNonce: 3), error: ARC.Errors.presentationLimitExceeded)
        // Test that using an incorrect presentationLimit throws an error
        XCTAssertThrowsError(try smallPresentationState.update(presentationContext: context2, presentationLimit: 9), error: ARC.Errors.invalidPresentationLimit)
        XCTAssertThrowsError(try smallPresentationState.update(presentationContext: Data("context 4".utf8), presentationLimit: 0), error: ARC.Errors.invalidPresentationLimit)

        var largePresentationState = ARC.PresentationState()
        for presentationLimit in 1..<100 {
            let presentationContext = Data("presentationContext\(presentationLimit)".utf8)
            for _ in 0..<presentationLimit {
                let nonce = try largePresentationState.update(presentationContext:presentationContext, presentationLimit: presentationLimit)
                XCTAssert(nonce < presentationLimit)
                // Test that reusing a nonce for a presentationContext throws an error
                XCTAssertThrowsError(try largePresentationState.update(presentationContext: presentationContext, presentationLimit: presentationLimit, optionalNonce: nonce), error: ARC.Errors.presentationLimitExceeded)
            }
            // Test that exceeding the rate limit for a presentationContext throws an error
            XCTAssertThrowsError(try largePresentationState.update(presentationContext: presentationContext, presentationLimit: presentationLimit), error: ARC.Errors.presentationLimitExceeded)
            XCTAssertEqual(largePresentationState.state[presentationContext]!.1.count, presentationLimit)
            // Test that using an incorrect presentationLimit throws an error
            XCTAssertThrowsError(try largePresentationState.update(presentationContext: presentationContext, presentationLimit: presentationLimit-1), error: ARC.Errors.invalidPresentationLimit)
        }
    }
}
