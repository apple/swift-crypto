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
@testable import _CryptoExtras
import XCTest

@available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 2.0, *)
final class ARCAPITests: XCTestCase {

    func testVectors() throws {
        let data = ARCEncodedTestVector.data(using: .utf8)!
        let decoder = JSONDecoder()
        for vector in try decoder.decode([ARCTestVector].self, from: data) {
            try testVector(vector)
        }
    }

    func testVector(_ vector: ARCTestVector) throws {
        // [Issuer] Create the server secrets.
        let privateKey = try P384._ARCV1.PrivateKey(rawRepresentation: Data(
            hexString: vector.ServerKey.x0 + vector.ServerKey.x1 + vector.ServerKey.x2 + vector.ServerKey.xb
        ))

        // [Issuer] Serialize public key to share with client (other serializations may be available).
        let publicKeyBytes = privateKey.publicKey.rawRepresentation

        // [CHECK] Public key matches test vector.
        XCTAssertEqual(
            publicKeyBytes.hexString,
            vector.ServerKey.X0 + vector.ServerKey.X1 + vector.ServerKey.X2
        )

        // [Issuer] Define a request context to share with the client.
        let requestContext = try Data(hexString: vector.CredentialRequest.request_context)

        // [Verifier] Define a presentation context and presentation limit (e.g. rate-limit).
        let presentationContext = try Data(hexString: vector.Presentation1.presentation_context)
        let presentationLimit = 2

        // [Client] Obtain public key, request context, presentation context, and presentation limit out of band.
        _ = (publicKeyBytes, requestContext, presentationContext, presentationLimit)

        // [Client] Obtain public key out of band (other serializations may be available).
        let publicKey = try P384._ARCV1.PublicKey(rawRepresentation: publicKeyBytes)

        // [Client] Prepare a credential request using fixed values from test vector.
        let precredential = try publicKey.prepareCredentialRequest(
            requestContext: requestContext,
            m1: P384._ARCV1.H2G.G.Scalar(bytes: Data(hexString: vector.CredentialRequest.m1)),
            r1: P384._ARCV1.H2G.G.Scalar(bytes: Data(hexString: vector.CredentialRequest.r1)),
            r2: P384._ARCV1.H2G.G.Scalar(bytes: Data(hexString: vector.CredentialRequest.r2))
        )

        // [Client -> Issuer] Send the credential request.
        let credentialRequestBytes = precredential.credentialRequest.rawRepresentation

        // [CHECK] Credential request scalars match test vector.
        XCTAssertEqual(
            credentialRequestBytes[..<(2 * P384.compressedx962PointByteCount)].hexString,
            vector.CredentialRequest.m1_enc + vector.CredentialRequest.m2_enc
        )

        // [Issuer] Receive the credential request.
        let credentialRequest = try P384._ARCV1.CredentialRequest(rawRepresentation: credentialRequestBytes)

        // [Issuer] Generate a credential response with fixed value from test vector.
        let credentialResponse = try privateKey.issue(
            credentialRequest,
            b: P384._ARCV1.H2G.G.Scalar(bytes: Data(hexString: vector.CredentialResponse.b))
        )

        // [Issuer -> Client] Send the credential response.
        let credentialResponseBytes = credentialResponse.rawRepresentation

        // [CHECK] Credential response scalars match test vector, excluding proof.
        XCTAssertEqual(
            credentialResponseBytes[..<(6 * P384.compressedx962PointByteCount)].hexString,
            vector.CredentialResponse.U
            + vector.CredentialResponse.enc_U_prime
            + vector.CredentialResponse.X0_aux
            + vector.CredentialResponse.X1_aux
            + vector.CredentialResponse.X2_aux
            + vector.CredentialResponse.H_aux
        )

        // [Client] Receive the credential response.
        let _ = try P384._ARCV1.CredentialResponse(rawRepresentation: credentialResponseBytes)

        // [Client] Generate a credential.
        var credential = try publicKey.finalize(credentialResponse, for: precredential)

        // [CHECK] Credential matches test vector.
        XCTAssertEqual(credential.backing.U.oprfRepresentation.hexString, vector.Credential.U)
        XCTAssertEqual(credential.backing.UPrime.oprfRepresentation.hexString, vector.Credential.U_prime)
        XCTAssertEqual(credential.backing.X1.oprfRepresentation.hexString, vector.Credential.X1)
        XCTAssertEqual(credential.backing.m1.rawRepresentation.hexString, vector.Credential.m1)

        // [Client] Make a presentation from the credential for a presentation prefix.
        let (presentation, _) = try credential.makePresentation(
            context: presentationContext,
            presentationLimit: presentationLimit,
            fixedNonce: Int(vector.Presentation1.nonce.dropFirst(2), radix: 16)!,
            a: P384._ARCV1.H2G.G.Scalar(bytes: Data(hexString: vector.Presentation1.a)),
            r: P384._ARCV1.H2G.G.Scalar(bytes: Data(hexString: vector.Presentation1.r)),
            z: P384._ARCV1.H2G.G.Scalar(bytes: Data(hexString: vector.Presentation1.z))
        )

        // NOTE: The presentation proof depends on randomly generated blinding factors. This layer doesn't expose
        //       internal methods for fixing these values
        //
        //       Here, we'll check that the presentation, excluding the proof, with the fixed scalars and nonce, matches
        //       the presentation from the test vector.
        //
        //       Then, for the remainder of this test, we'll cut over to the presentation from the test vector.
        //
        //       Proof generation and verification, in general, is well covered by other tests; and proof validity, for
        //       ARC specifically, is covered in the end-to-end tests in ARCPublicAPITests.

        // [CHECK]: Check presentation (excluding proof) matches test vector.
        XCTAssertEqual(presentation.backing.U.oprfRepresentation.hexString, vector.Presentation1.U)
        XCTAssertEqual(presentation.backing.UPrimeCommit.oprfRepresentation.hexString, vector.Presentation1.U_prime_commit)
        XCTAssertEqual(presentation.backing.m1Commit.oprfRepresentation.hexString, vector.Presentation1.m1_commit)
        XCTAssertEqual(presentation.backing.tag.oprfRepresentation.hexString, vector.Presentation1.tag)

        // [CHECK]: Serialization of presentation (ecluding proof) matches spec.
        XCTAssertEqual(
            presentation.rawRepresentation[..<(4 * P384.compressedx962PointByteCount)].hexString,
            vector.Presentation1.U
            + vector.Presentation1.U_prime_commit
            + vector.Presentation1.m1_commit
            + vector.Presentation1.tag
        )
        XCTAssertEqual(
            presentation.rawRepresentation[(4 * P384.compressedx962PointByteCount)...].hexString.count,
            vector.Presentation1.proof.count
        )

        // [CHECK]: Full serialization of presentation, including proof from test vector, matches test vector.
        let testVectorPresentationBytes = try Data(
            hexString: vector.Presentation1.U
            + vector.Presentation1.U_prime_commit
            + vector.Presentation1.m1_commit
            + vector.Presentation1.tag
            + vector.Presentation1.proof
        )
        XCTAssertEqual(
            try P384._ARCV1.Presentation(rawRepresentation: testVectorPresentationBytes).rawRepresentation.hexString,
            testVectorPresentationBytes.hexString
        )

        // [Verifier] Receive the presentation (and the nonce, out of band).
        let receivedPresentation = try P384._ARCV1.Presentation(rawRepresentation: testVectorPresentationBytes)
        let nonce = Int(vector.Presentation1.nonce.dropFirst(2), radix: 16)!

        // [Verifier] Verify the presentation.
        let validPresentation = try privateKey.verify(
            receivedPresentation,
            requestContext: requestContext,
            presentationContext: presentationContext,
            presentationLimit: presentationLimit,
            nonce: nonce
        )
        XCTAssertTrue(validPresentation)
    }
}
