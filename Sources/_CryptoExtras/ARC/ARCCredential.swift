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
import Foundation

extension ARC {
    struct Credential<H2G: HashToGroup> {
        typealias Group = H2G.G
        let m1: Group.Scalar
        let U: Group.Element
        let UPrime: Group.Element
        let X1: Group.Element
        let ciphersuite: Ciphersuite<H2G>
        let generatorG: Group.Element
        let generatorH: Group.Element
        let presentationLimit: Int
        var presentationNonces: [Data: Set<Int>]

        init(credentialResponse: CredentialResponse<H2G>, credentialRequest: CredentialRequest<H2G>, clientSecrets: ClientSecrets<Group.Scalar>, serverPublicKey: ServerPublicKey<H2G>, ciphersuite: Ciphersuite<H2G>, generatorG: Group.Element, generatorH: Group.Element,  presentationLimit: Int) throws {
            // Verify credential response proof
            guard
                try credentialResponse.verify(request: credentialRequest, serverPublicKey: serverPublicKey, generatorG: generatorG, generatorH: generatorH)
            else {
                throw ARC.Errors.invalidProof
            }

            // Decrypt Enc(U') from the credential response, to get U'
            let UPrime = credentialResponse.encUPrime - credentialResponse.X0Aux - clientSecrets.r1 * credentialResponse.X1Aux - clientSecrets.r2 * credentialResponse.X2Aux

            let presentationNonces = [Data: Set<Int>]()
            self = Self(m1: clientSecrets.m1, U: credentialResponse.U, UPrime: UPrime, X1: serverPublicKey.X1, presentationLimit: presentationLimit, presentationNonces: presentationNonces, ciphersuite: ciphersuite, generatorG: generatorG, generatorH: generatorH)
        }

        internal init(m1: Group.Scalar, U: Group.Element, UPrime: Group.Element, X1: Group.Element, presentationLimit: Int, presentationNonces: [Data: Set<Int>], ciphersuite: Ciphersuite<H2G>, generatorG: Group.Element, generatorH: Group.Element) {
            self.m1 = m1
            self.U = U
            self.UPrime = UPrime
            self.X1 = X1
            self.presentationLimit = presentationLimit
            self.presentationNonces = presentationNonces
            self.ciphersuite = ciphersuite
            self.generatorG = generatorG
            self.generatorH = generatorH
        }

        mutating func makePresentation(presentationContext: Data, a: Group.Scalar = Group.Scalar.random, r: Group.Scalar = Group.Scalar.random, z: Group.Scalar = Group.Scalar.random, optionalNonce: Int? = nil) throws -> (Presentation<H2G>, Int) {
            // If optionalNonce is set, use that nonce (eg for test vectors).
            // Otherwise, generate a random nonce that has not yet been used.
            var nonce = optionalNonce != nil ? optionalNonce! : Int.random(in: 0..<self.presentationLimit)

            // Store the nonce in presentationNonces for that presentationContext.
            if self.presentationNonces[presentationContext] != nil {
                if self.presentationNonces[presentationContext]!.count >= self.presentationLimit {
                    throw ARC.Errors.presentationLimitExceeded
                }
                while self.presentationNonces[presentationContext]!.contains(nonce) {
                    if optionalNonce == nil {
                        // Randomly generated nonce collides with existing nonce for presentationContext
                        nonce = Int.random(in: 0..<self.presentationLimit)
                    } else {
                        // optionalNonce collides with existing nonce for presentationContext
                        throw ARC.Errors.presentationLimitExceeded
                    }
                }
                self.presentationNonces[presentationContext]!.insert(nonce)
            } else {
                self.presentationNonces[presentationContext] = [nonce]
            }

            let presentation = try Presentation<H2G>(credential: self, a: a, r: r, z: z, presentationContext: presentationContext, nonce: nonce, generatorG: self.generatorG, generatorH: self.generatorH)
            return (presentation, nonce)
        }
    }
}
