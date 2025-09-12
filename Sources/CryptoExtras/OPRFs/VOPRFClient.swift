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
    struct VerifiableClient<H2G: HashToGroup> {
        fileprivate let client: OPRF.Client<H2G>
        typealias G = H2G.G
        
        init(ciphersuite: Ciphersuite<H2G>, v8CompatibilityMode: Bool = false, mode: OPRF.Mode) throws {
            if mode != .partiallyOblivious && mode != .verifiable {
                throw OPRF.Errors.incompatibleMode
            }
            
            self.client = .init(mode: mode, ciphersuite: ciphersuite, v8CompatibilityMode: v8CompatibilityMode)
        }
        
        func blindMessage(_ message: Data, blind: G.Scalar = G.Scalar.random) -> (blind: G.Scalar, blindedElement: G.Element) {
            self.client.blindMessage(message, blind: blind)
        }
        
        fileprivate func v8Finalize(message: Data, info: Data?, blind: G.Scalar, evaluatedElement: G.Element, proof: DLEQProof<G.Scalar>, publicKey: G.Element) throws -> Data {
            precondition(self.client.mode == .verifiable)
            let setupCtx = setupContext(mode: client.mode, suite: client.ciphersuite, v8CompatibilityMode: self.client.v8CompatibilityMode)
            let contextDST = "Context-".data(using: .utf8)! + setupCtx
            
            let ctx = contextDST + I2OSP(value: (info?.count ?? 0), outputByteCount: 2) + (info ?? Data())
            
            let m = try H2G.hashToScalar(ctx, domainSeparationString: setupCtx)
            let t = m * G.Element.generator
            
            let u = publicKey + t
            
            let blindedElement = self.blindMessage(message, blind: blind).blindedElement
            guard try DLEQ<H2G>.verifyProof(A: H2G.G.Element.generator, B: u,
                                            CDs: [(C: evaluatedElement, D: blindedElement)],
                                            proof: proof,
                                            dst: setupContext(mode: client.mode, suite: client.ciphersuite, v8CompatibilityMode: self.client.v8CompatibilityMode), v8CompatibilityMode: self.client.v8CompatibilityMode) else {
                throw OPRF.Errors.invalidProof
            }
            
            return try self.client.finalize(message: message, info: info, blind: blind, evaluatedElement: evaluatedElement)
            
        }
        
        func finalize(message: Data, info: Data?, blind: G.Scalar, evaluatedElement: G.Element, proof: DLEQProof<G.Scalar>, publicKey: G.Element) throws -> Data {
            if self.client.v8CompatibilityMode { return try v8Finalize(message: message, info: info, blind: blind, evaluatedElement: evaluatedElement, proof: proof, publicKey: publicKey) }
            
            let hasInfo = (info != nil)
            if hasInfo && (self.client.mode == .verifiable) {
                throw OPRF.Errors.invalidModeForInfo
            }
            
            let setupCtx = setupContext(mode: client.mode, suite: client.ciphersuite, v8CompatibilityMode: self.client.v8CompatibilityMode)
            let blindedElement = self.blindMessage(message, blind: blind).blindedElement

            if self.client.mode == .verifiable {
                guard try DLEQ<H2G>.verifyProof(A: H2G.G.Element.generator, B: publicKey,
                                                CDs: [(C: blindedElement, D: evaluatedElement)],
                                                proof: proof,
                                                dst: setupContext(mode: client.mode, suite: client.ciphersuite, v8CompatibilityMode: self.client.v8CompatibilityMode), v8CompatibilityMode: self.client.v8CompatibilityMode) else {
                    throw OPRF.Errors.invalidProof
                }
                
                return try self.client.finalize(message: message, info: info, blind: blind, evaluatedElement: evaluatedElement)
            }
            
            precondition(self.client.mode == .partiallyOblivious)
            let framedInfo = Data("Info".utf8) + I2OSP(value: info!.count, outputByteCount: 2) + info!
            
            let m = try H2G.hashToScalar(framedInfo, domainSeparationString: setupCtx)
            let T = m * G.Element.generator
            
            let tweakedKey = T + publicKey
            guard try DLEQ<H2G>.verifyProof(A: H2G.G.Element.generator, B: tweakedKey,
                                            CDs: [(C: evaluatedElement, D: blindedElement)],
                                            proof: proof,
                                            dst: setupContext(mode: client.mode, suite: client.ciphersuite, v8CompatibilityMode: self.client.v8CompatibilityMode), v8CompatibilityMode: self.client.v8CompatibilityMode) else {
                throw OPRF.Errors.invalidProof
            }
            
            return try self.client.finalize(message: message, info: info, blind: blind, evaluatedElement: evaluatedElement)
        }
        
    }
}
