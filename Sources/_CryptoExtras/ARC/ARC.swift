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

/// Anonymous Rate-Limited Credentials (ARC) using the CMZ14 MACGGM construction, as defined in
/// https://chris-wood.github.io/draft-arc/draft-yun-cfrg-arc.html
@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
enum ARC {}

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
extension ARC {
    static let domain = "ARCV1-P384"

    enum Errors: Error {
        case invalidProof
        case invalidPresentationLimit
        case presentationLimitExceeded
        case incorrectRequestDataSize
        case incorrectResponseDataSize
        case incorrectCredentialDataSize
        case incorrectPresentationDataSize
        case incorrectProofDataSize
        case incorrectServerCommitmentsSize
        case incorrectPrivateKeyDataSize
        case incorrectPublicKeyDataSize
    }

    /// Ciphersuites for Anonymous Rate-Limited Credentials (ARC)
    struct Ciphersuite<H2G: HashToGroup> {
        let suiteID: Int

        init(_ h2g: H2G.Type) {
            switch h2g.self {
            case is HashToCurveImpl<P256>.Type:
                self.suiteID = 3
            case is HashToCurveImpl<P384>.Type:
                self.suiteID = 4
            case is HashToCurveImpl<P521>.Type:
                self.suiteID = 5
            default:
                fatalError("Anonymous Rate-Limited Credentials (ARC) only support corecrypto H2G.")
            }
        }
    }

    static func getGenerators<H2G: HashToGroup>(suite _: Ciphersuite<H2G>) -> (
        generatorG: H2G.G.Element, generatorH: H2G.G.Element
    ) {
        let generatorG = H2G.G.Element.generator
        let generatorH = H2G.hashToGroup(generatorG.oprfRepresentation, domainSeparationString: Data(("HashToGroup-" + ARC.domain + "generatorH").utf8))
        return (generatorG, generatorH)
    }
}
