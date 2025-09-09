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
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
extension ARC {
    struct ServerPrivateKey<Scalar: GroupScalar> {
        let x0: Scalar
        let x1: Scalar
        let x2: Scalar
        let x0Blinding: Scalar

        init(x0: Scalar, x1: Scalar, x2: Scalar, x0Blinding: Scalar) {
            self.x0 = x0
            self.x1 = x1
            self.x2 = x2
            self.x0Blinding = x0Blinding
        }
    }

    struct ServerPublicKey<H2G: HashToGroup> {
        typealias Group = H2G.G
        let X0: Group.Element
        let X1: Group.Element
        let X2: Group.Element

        init(X0: Group.Element, X1: Group.Element, X2: Group.Element) {
            self.X0 = X0
            self.X1 = X1
            self.X2 = X2
        }

        init(serverPrivateKey: ServerPrivateKey<Group.Scalar>, generatorG: Group.Element, generatorH: Group.Element) {
            self.X0 = serverPrivateKey.x0 * generatorG + serverPrivateKey.x0Blinding * generatorH
            self.X1 = serverPrivateKey.x1 * generatorH
            self.X2 = serverPrivateKey.x2 * generatorH
        }
     }

    struct Server<H2G: HashToGroup> {
        typealias Group = H2G.G
        let serverPrivateKey: ServerPrivateKey<Group.Scalar>
        let serverPublicKey: ServerPublicKey<H2G>
        let ciphersuite: Ciphersuite<H2G>
        let generatorG: Group.Element
        let generatorH: Group.Element

        init(ciphersuite: Ciphersuite<H2G>, x0: Group.Scalar = Group.Scalar.random, x1: Group.Scalar = Group.Scalar.random, x2: Group.Scalar = Group.Scalar.random, x0Blinding: Group.Scalar = Group.Scalar.random
        ) {
            self.ciphersuite = ciphersuite
            (self.generatorG, self.generatorH) = ARC.getGenerators(suite: ciphersuite)

            self.serverPrivateKey = ServerPrivateKey(x0: x0, x1: x1, x2: x2, x0Blinding: x0Blinding)
            self.serverPublicKey = ServerPublicKey(serverPrivateKey: self.serverPrivateKey, generatorG: self.generatorG, generatorH: self.generatorH)
        }

        func respond(credentialRequest: CredentialRequest<H2G>, b: Group.Scalar = Group.Scalar.random) throws -> CredentialResponse<H2G> {
            guard
                try credentialRequest.verify(generatorG: generatorG, generatorH: generatorH, ciphersuite: self.ciphersuite)
            else {
                throw ARC.Errors.invalidProof
            }
            return try CredentialResponse(
                request: credentialRequest,
                serverPrivateKey: self.serverPrivateKey,
                serverPublicKey: self.serverPublicKey,
                generatorG: generatorG,
                generatorH: generatorH,
                b: b,
                ciphersuite: self.ciphersuite
            )
        }

        func verify(presentation: Presentation<H2G>, requestContext: Data, presentationContext: Data, presentationLimit: Int, nonce: Int) throws -> Bool {
            let m2 = try H2G.hashToScalar(requestContext, domainSeparationString: Data((self.ciphersuite.domain + "requestContext").utf8))
            return try presentation.verify(
                serverPrivateKey: self.serverPrivateKey,
                X1: self.serverPublicKey.X1,
                m2: m2,
                presentationContext: presentationContext,
                presentationLimit: presentationLimit,
                nonce: nonce,
                generatorG: generatorG,
                generatorH: generatorH,
                ciphersuite: self.ciphersuite
            )
        }
    }
}
