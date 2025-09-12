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
extension OPRF {
    struct Client<H2G: HashToGroup> {
        let mode: Mode
        let ciphersuite: Ciphersuite<H2G>
        let v8CompatibilityMode: Bool
        typealias G = H2G.G
        
        init(ciphersuite: Ciphersuite<H2G>) {
            self = Self(mode: .base, ciphersuite: ciphersuite)
        }
        
        internal init(mode: Mode, ciphersuite: Ciphersuite<H2G>, v8CompatibilityMode: Bool = false) {
            self.mode = mode
            self.ciphersuite = ciphersuite
            self.v8CompatibilityMode = v8CompatibilityMode
        }
        
        func blindMessage(_ message: Data, blind: G.Scalar = G.Scalar.random) -> (blind: G.Scalar, blindedElement: G.Element) {
            let dst = "HashToGroup-".data(using: .utf8)! + setupContext(mode: mode, suite: ciphersuite, v8CompatibilityMode: self.v8CompatibilityMode)
            let P: G.Element = H2G.hashToGroup(message, domainSeparationString: dst)
            let blindedElement = blind * P
            return (blind: blind, blindedElement: blindedElement)
        }
        
        func unblind(blind: G.Scalar, evaluatedElement: G.Element) -> G.Element {
            return (blind ^ (-1)) * evaluatedElement
        }
        
        func finalize(message: Data, info: Data?, blind: G.Scalar, evaluatedElement: G.Element) throws -> Data {
            let unblinded = unblind(blind: blind,
                                    evaluatedElement: evaluatedElement)
            
            return Data(H2G.H.hash(data: composeFinalizeContext(message: message, info: info, unblindedElement: unblinded, ciphersuite: ciphersuite, mode: mode, v8CompatibilityMode: self.v8CompatibilityMode)))
        }
        
    }
}
