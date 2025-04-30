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
    struct Server<H2G: HashToGroup> {
        typealias G = H2G.G
        let mode: Mode
        let ciphersuite: Ciphersuite<H2G>
        let privateKey: G.Scalar
        let v8CompatibilityMode: Bool
        
        init(ciphersuite: Ciphersuite<H2G>, privateKey: G.Scalar = G.Scalar.random) {
            self.init(mode: .base, ciphersuite: ciphersuite, privateKey: privateKey)
        }
        
        internal init(mode: Mode, ciphersuite: Ciphersuite<H2G>, privateKey: G.Scalar = G.Scalar.random, v8CompatibilityMode: Bool = false) {
            self.mode = mode
            self.ciphersuite = ciphersuite
            self.privateKey = privateKey
            self.v8CompatibilityMode = v8CompatibilityMode
        }
        
        var publicKey: G.Element {
            privateKey * G.Element.generator
        }
        
        func evaluate(blindedElement: G.Element, info: Data? = nil, proofScalar: G.Scalar = G.Scalar.random) throws ->
        (G.Element, DLEQProof<H2G.G.Element.Scalar>?) {
            let dst = setupContext(mode: mode, suite: ciphersuite, v8CompatibilityMode: self.v8CompatibilityMode)
            
            if v8CompatibilityMode { return try v8Evaluate(blindedElement: blindedElement, info: info, proofScalar: proofScalar) }
            
            if mode == .base || mode == .verifiable {
                let evaluatedElement = self.privateKey * blindedElement
                if mode == .base { return (evaluatedElement, nil) }
                
                let proof = try DLEQ<H2G>.proveEquivalenceBetween(k: self.privateKey,
                                                                  A: G.Element.generator,
                                                                  B: (self.privateKey * G.Element.generator),
                                                                  CDs: [(C: blindedElement, D: evaluatedElement)],
                                                                  dst: dst,
                                                                  proofScalar: proofScalar, v8CompatibilityMode: self.v8CompatibilityMode)
                return (evaluatedElement, proof)
            }
            
            precondition(mode == .partiallyOblivious)
            let framedInfo = Data("Info".utf8) + I2OSP(value: info!.count, outputByteCount: 2) + info!
            
            let m = try H2G.hashToScalar(framedInfo, domainSeparationString: dst)
            let t = privateKey + m
            
            let evaluatedElement = (t ^ (-1)) * blindedElement
            let proof = try DLEQ<H2G>.proveEquivalenceBetween(k: t,
                                                              A: G.Element.generator,
                                                              B: (t * G.Element.generator),
                                                              CDs: [(C: evaluatedElement, D: blindedElement)],
                                                              dst: dst,
                                                              proofScalar: proofScalar, v8CompatibilityMode: self.v8CompatibilityMode)
            return (evaluatedElement, proof)
        }
        
        internal func v8Evaluate(blindedElement: G.Element, info: Data? = nil, proofScalar: G.Scalar = G.Scalar.random) throws ->
        (G.Element, DLEQProof<H2G.G.Element.Scalar>?) {
            precondition(self.mode == .verifiable || self.mode == .base)
            let setupCtx = setupContext(mode: mode, suite: ciphersuite, v8CompatibilityMode: self.v8CompatibilityMode)
            let contextDST = "Context-".data(using: .utf8)! + setupCtx
            
            let ctx = contextDST + I2OSP(value: (info?.count ?? 0), outputByteCount: 2) + (info ?? Data())
            
            let m = try H2G.hashToScalar(ctx, domainSeparationString: setupCtx)
            let t = privateKey + m
            let evaluatedElement = (t ^ (-1)) * blindedElement
            
            guard self.mode != .base else {
                return (evaluatedElement, nil)
            }
            
            let proof = try DLEQ<H2G>.proveEquivalenceBetween(k: t,
                                                              A: G.Element.generator,
                                                              B: (t * G.Element.generator),
                                                              CDs: [(C: evaluatedElement, D: blindedElement)],
                                                              dst: setupCtx,
                                                              proofScalar: proofScalar, v8CompatibilityMode: self.v8CompatibilityMode)
            return (evaluatedElement, proof)
        }
        
        internal func verifyFinalize(msg: Data,
                                     output: Data,
                                     info: Data?) throws -> Bool {
            let dst = "HashToGroup-".data(using: .utf8)! + setupContext(mode: mode, suite: ciphersuite, v8CompatibilityMode: self.v8CompatibilityMode)
            let t: H2G.G.Element = H2G.hashToGroup(msg, domainSeparationString: dst)
            let (issuedElement, _): (H2G.G.Element, DLEQProof<H2G.G.Element.Scalar>?) = try evaluate(blindedElement: t, info: info)
            
            return output == Data(H2G.H.hash(data: composeFinalizeContext(message: msg, info: info, unblindedElement: issuedElement, ciphersuite: ciphersuite, mode: mode, v8CompatibilityMode: v8CompatibilityMode)))
        }
    }
}
