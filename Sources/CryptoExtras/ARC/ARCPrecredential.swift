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
    struct ClientSecrets<Scalar: GroupScalar> {
        let m1: Scalar // secret at request and verification
        let m2: Scalar // secret at request, public at verification (server expected to know value)
        let r1: Scalar // secret blinding factor for m1
        let r2: Scalar // secret blinding factor for m2

        init(m1: Scalar, m2: Scalar, r1: Scalar, r2: Scalar) {
            self.m1 = m1
            self.m2 = m2
            self.r1 = r1
            self.r2 = r2
        }
    }

    struct Precredential<H2G: HashToGroup> {
        typealias Group = H2G.G
        let clientSecrets: ClientSecrets<Group.Scalar>
        let serverPublicKey: ServerPublicKey<H2G>
        let ciphersuite: Ciphersuite<H2G>
        let generatorG: Group.Element
        let generatorH: Group.Element
        let credentialRequest: CredentialRequest<H2G>

        init(ciphersuite: Ciphersuite<H2G>, m1: Group.Scalar = Group.Scalar.random, requestContext: Data, r1: Group.Scalar = Group.Scalar.random, r2: Group.Scalar = Group.Scalar.random, serverPublicKey: ServerPublicKey<H2G>) throws {
            let m2 = try H2G.hashToScalar(requestContext, domainSeparationString: Data((ciphersuite.domain + "requestContext").utf8))
            self.clientSecrets = ClientSecrets(m1: m1, m2: m2, r1: r1, r2: r2)
            self.serverPublicKey = serverPublicKey
            self.ciphersuite = ciphersuite
            (self.generatorG, self.generatorH) = ARC.getGenerators(suite: ciphersuite)
            self.credentialRequest = try CredentialRequest(clientSecrets: self.clientSecrets, generatorG: generatorG, generatorH: generatorH, ciphersuite: ciphersuite)
        }

        func makeCredential(credentialResponse: CredentialResponse<H2G>) throws -> Credential<H2G> {
            return try Credential<H2G>(credentialResponse: credentialResponse, credentialRequest: self.credentialRequest, clientSecrets: self.clientSecrets, serverPublicKey: self.serverPublicKey, ciphersuite: self.ciphersuite, generatorG: self.generatorG, generatorH: self.generatorH)
        }
    }
}
