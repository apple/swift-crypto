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
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
extension OPRF {
    struct VerifiableServer<H2G: HashToGroup> {
        typealias G = H2G.G
        let server: OPRF.Server<H2G>
        
        init(ciphersuite: Ciphersuite<H2G>, privateKey: G.Scalar = G.Scalar.random, v8CompatibilityMode: Bool = false, mode: OPRF.Mode) throws {
            if mode != .partiallyOblivious && mode != .verifiable {
                throw OPRF.Errors.incompatibleMode
            }
            
            self.server = .init(mode: mode, ciphersuite: ciphersuite, privateKey: privateKey, v8CompatibilityMode: v8CompatibilityMode)
        }
        
        var publicKey: G.Element {
            server.publicKey
        }
        
        func evaluate(blindedElement: G.Element, info: Data? = nil, proofScalar: G.Scalar = G.Scalar.random) throws ->
        (G.Element, DLEQProof<H2G.G.Element.Scalar>) {
            let hasInfo = (info != nil)
            if hasInfo && self.server.mode == .verifiable && !server.v8CompatibilityMode {
                throw OPRF.Errors.invalidModeForInfo
            }
            
            let (evaluatedElement, proof) = try self.server.evaluate(blindedElement: blindedElement,
                                                                     info: info,
                                                                     proofScalar: proofScalar)
            
            return (evaluatedElement, proof!)
        }
        
        internal func verifyFinalize(msg: Data,
                                     output: Data,
                                     info: Data?) throws -> Bool {
            return try server.verifyFinalize(msg: msg, output: output, info: info)
        }
    }
}
