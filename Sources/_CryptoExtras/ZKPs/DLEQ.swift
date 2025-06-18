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

/// A DLEQ Proof as described in https://cfrg.github.io/draft-irtf-cfrg-voprf/draft-irtf-cfrg-voprf.html#name-generateproof
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct DLEQProof<GS: GroupScalar> {
    var c: GS
    var s: GS

    internal init(c: GS, s: GS) {
        self.c = c
        self.s = s
    }
}

// Discrete Log Equivalence Proof
// Proves that for a value kept secret k, the relation between B=k*A and D=k*C is such that log_A(B)==log_C(D)
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct DLEQ<H2G: HashToGroup> {
    typealias GE = H2G.G.Element
    
    static func composites(k: GE.Scalar? = nil, B: GE, dst: Data, CDs: [(C: GE, D: GE)], v8CompatibilityMode: Bool) throws -> (M: GE, Z: GE) {
        let seedDST = "Seed-".data(using: .utf8)! + dst
        
        let Bm = B.oprfRepresentation
        
        let h1Input = I2OSP(value: Bm.count, outputByteCount: 2) + Bm
        + I2OSP(value: seedDST.count, outputByteCount: 2) + seedDST
        let seed = Data(H2G.H.hash(data: h1Input))

        var M: GE?
        var Z: GE?

        for i in 0..<CDs.count {
            let pair = CDs[i]
            let Ci = pair.C
            let Di = pair.D

            let Cim = Ci.oprfRepresentation
            let Dim = Di.oprfRepresentation
            
            var h2input = I2OSP(value: seed.count, outputByteCount: 2) + seed
            + I2OSP(value: i, outputByteCount: 2)
            + I2OSP(value: Cim.count, outputByteCount: 2) + Cim
            + I2OSP(value: Dim.count, outputByteCount: 2) + Dim
            if v8CompatibilityMode {
                let compositeDST = "Composite-".data(using: .utf8)! + dst
                h2input = h2input + I2OSP(value: compositeDST.count, outputByteCount: 2) + compositeDST
            } else {
                h2input = h2input + Data("Composite".utf8)
            }

            let di = try H2G.hashToScalar(h2input, domainSeparationString: dst)
            if let m = M {
                M = (di * Ci) + m
            } else {
                M = (di * Ci)
            }
            
            if k == nil {
                if let z = Z {
                    Z = (di * Di) + z
                } else {
                    Z = (di * Di)
                }
            }
        }

        if k != nil {
            Z = k! * M!
        }

        return (M: M!, Z: Z!)
    }
    
    static func composeChallenge(dst: Data, B: GE, M: GE, Z: GE, T2: GE, T3: GE, v8CompatibilityMode: Bool) throws -> GE.Scalar {
        let Bm = B.oprfRepresentation
        let A0 = M.oprfRepresentation
        let A1 = Z.oprfRepresentation
        let A2 = T2.oprfRepresentation
        let A3 = T3.oprfRepresentation
        
        var h2Input = I2OSP(value: Bm.count, outputByteCount: 2) + Bm +
        I2OSP(value: A0.count, outputByteCount: 2) + A0 +
        I2OSP(value: A1.count, outputByteCount: 2) + A1 +
        I2OSP(value: A2.count, outputByteCount: 2) + A2 +
        I2OSP(value: A3.count, outputByteCount: 2) + A3
        
        if v8CompatibilityMode {
            let challengeDST = "Challenge-".data(using: .utf8)! + dst
            h2Input = h2Input + I2OSP(value: challengeDST.count, outputByteCount: 2) + challengeDST
            
        } else {
            let challengeDST = "Challenge".data(using: .utf8)!
            h2Input = h2Input + challengeDST
        }
        
        return try H2G.hashToScalar(h2Input, domainSeparationString: dst)
    }
    
    static func proveEquivalenceBetween(k: GE.Scalar,
                                        A: GE,
                                        B: GE,
                                        CDs: [(C: GE, D: GE)],
                                        dst: Data,
                                        proofScalar: GE.Scalar, v8CompatibilityMode: Bool) throws -> DLEQProof<GE.Scalar> {
        var M: GE
        var Z: GE
        
        let comp = try composites(k: k, B: B, dst: dst, CDs: CDs, v8CompatibilityMode: v8CompatibilityMode)
        M = comp.M
        Z = comp.Z
        
        let r = proofScalar

        let t2 = r * A
        let t3 = r * M
        
        let c = try composeChallenge(dst: dst, B: B, M: M, Z: Z, T2: t2, T3: t3, v8CompatibilityMode: v8CompatibilityMode)
        
        let s = (r - c * k)
        
        return DLEQProof<GE.Scalar>(c: c, s: s)
    }
    
    static func verifyProof(A: GE,
                            B: GE,
                            CDs: [(C: GE, D: GE)],
                            proof: DLEQProof<GE.Scalar>, dst: Data, v8CompatibilityMode: Bool) throws -> Bool {
        let composites = try composites(B: B, dst: dst, CDs: CDs, v8CompatibilityMode: v8CompatibilityMode)
        let t2 = (proof.s * A) + (proof.c * B)
        let t3 = ((proof.s * composites.M) + (proof.c * composites.Z))
        
        let c = try composeChallenge(dst: dst, B: B, M: composites.M, Z: composites.Z, T2: t2, T3: t3, v8CompatibilityMode: v8CompatibilityMode)
        
        return c == proof.c
    }
}
