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
import CryptoExtras  // NOTE: No @testable import, because we want to test the public API.
import XCTest

@available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 2.0, *)
final class ARCPublicAPITests: XCTestCase {

    func testARCEndToEnd() throws {
        // [Issuer] Create the server secrets (other initializers will be available).
        let privateKey = P256._ARCV1.PrivateKey()

        // [Issuer] Serialize public key to share with client (other serializations may be available).
        let publicKeyBytes = privateKey.publicKey.rawRepresentation

        // [Issuer] Define a request context to share with the client.
        let requestContext = Data("shared request context".utf8)

        // [Verifier] Define a presentation context and presentation limit (e.g. rate-limit).
        let (presentationContext, presentationLimit) = (Data("shared presentation context".utf8), 2)

        // [Client] Obtain public key, request context, presentation context, and presentation limit out of band.
        _ = (publicKeyBytes, requestContext, presentationContext, presentationLimit)

        // [Client] Obtain public key out of band (other serializations may be available).
        let publicKey = try P256._ARCV1.PublicKey(rawRepresentation: publicKeyBytes)

        // [Client] Prepare a credential request.
        let precredential = try publicKey.prepareCredentialRequest(requestContext: requestContext)

        // [Client -> Issuer] Send the credential request.
        let credentialRequestBytes = precredential.credentialRequest.rawRepresentation

        // [Issuer] Receive the credential request.
        let credentialRequest = try P256._ARCV1.CredentialRequest(rawRepresentation: credentialRequestBytes)

        // [Issuer] Generate a credential response.
        let credentialResponse = try privateKey.issue(credentialRequest)

        // [Issuer -> Client] Send the credential response.
        let credentialResponseBytes = credentialResponse.rawRepresentation

        // [Client] Receive the credential response.
        let _ = try P256._ARCV1.CredentialResponse(rawRepresentation: credentialResponseBytes)

        // [Client] Generate a credential.
        // NOTE: This is a var because it enforces the presentation limits for each presentation prefix.
        var credential = try publicKey.finalize(credentialResponse, for: precredential)

        // [Client] Make a presentation from the credential for a presentation prefix.
        // NOTE: On first presentation, the presentation limit provided is now set, and enforced going forward.
        let (presentation, nonce) = try credential.makePresentation(
            context: presentationContext,
            presentationLimit: presentationLimit
        )

        // [Client -> Verifier] Send the presentation.
        let presentationBytes = presentation.rawRepresentation

        // [Verifier] Receive the presentation.
        let _ = try P256._ARCV1.Presentation(rawRepresentation: presentationBytes)

        // [Verifier] Verify the presentation.
        let validPresentation = try privateKey.verify(
            presentation,
            requestContext: requestContext,
            presentationContext: presentationContext,
            presentationLimit: presentationLimit,
            nonce: nonce
        )
        XCTAssertTrue(validPresentation)

        // [Verifier] Enforce rate limit with a combination of tag, nonce, presentation context, and presentation limit.
        _ = (presentation.tag, presentationContext, presentationLimit)
    }

    func testCrendentialEnforcesPresentationLimitLocally() throws {
        let privateKey = P256._ARCV1.PrivateKey()
        let publicKey = privateKey.publicKey
        let requestContext = Data("shared request context".utf8)
        let presentationContext = Data("shared presentation context".utf8)
        let presentationLimit = 2

        let precredential = try publicKey.prepareCredentialRequest(requestContext: requestContext)
        let credentialResponse = try privateKey.issue(precredential.credentialRequest)
        var credential = try publicKey.finalize(credentialResponse, for: precredential)

        for _ in 0..<presentationLimit {
            _ = try credential.makePresentation(context: presentationContext, presentationLimit: presentationLimit)
        }

        XCTAssertThrowsError(
            try credential.makePresentation(context: presentationContext, presentationLimit: presentationLimit)
        ) { error in
            XCTAssertEqual(String(describing: error), "presentationLimitExceeded")
        }
    }
}
