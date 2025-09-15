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
@testable import CryptoExtras
import XCTest

struct OPRFSuite: Codable {
    let groupDST: String
    let suiteName: String?
    let identifier: String?
    let suiteID: Int?
    let mode: Int
    let skSm: String
    let pkSm: String?
    let vectors: [OPRFTestVector]
}

struct DLEQProofVector: Codable {
    let proof: String
    let r: String
}

struct OPRFTestVector: Codable {
    let Batch: Int
    let Blind: String
    let BlindedElement: String
    let EvaluationElement: String
    let Info: String?
    let Input: String
    let Output: String
    let Proof: DLEQProofVector?
    let result: String?
    let comment: String?
}

enum Result: String {
    case success = "success"
    case invalidProof = "invalidProof"
    case invalidOPRFOutput = "invalidOPRFOutput"
}

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
class ECVOPRFTests: XCTestCase {
    func testSuite<G: SupportedCurveDetailsImpl>(suite: OPRFSuite, C: G.Type, modeValue: Int, v8DraftCompatible: Bool) throws {
        switch modeValue {
        case OPRF.Mode.base.rawValue:
            try testBaseSuite(suite: suite, C: C, v8DraftCompatible: v8DraftCompatible)
        case OPRF.Mode.verifiable.rawValue:
            try testVerifiableSuite(suite: suite, C: C, v8DraftCompatible: v8DraftCompatible, mode: .verifiable)
        case OPRF.Mode.partiallyOblivious.rawValue:
            try testVerifiableSuite(suite: suite, C: C, v8DraftCompatible: v8DraftCompatible, mode: .partiallyOblivious)
        default:
            fatalError("Unknown mode")
        }
    }

    func testBaseSuite<G: SupportedCurveDetailsImpl>(suite: OPRFSuite, C: G.Type, v8DraftCompatible: Bool) throws {
        print("Testing \(suite.suiteName ?? suite.identifier!) in base mode.")

        let privateKey = try GroupImpl<G>.Scalar(bytes: Data(hexString: suite.skSm))
        let ciphersuite = OPRF.Ciphersuite(HashToCurveImpl<G>.self)

        for vector in suite.vectors {
            if vector.Batch != 1 {
                continue
            }

            let client = OPRF.Client(mode: .base, ciphersuite: ciphersuite, v8CompatibilityMode: v8DraftCompatible)
            let blindTestVector = try GroupImpl<G>.Scalar(bytes: Data(hexString: vector.Blind))
            let input = try Data(hexString: vector.Input)

            let (blind, blindedElement) = client.blindMessage(input, blind: blindTestVector)

            XCTAssert(blindTestVector == blind)
            XCTAssert(blindedElement.oprfRepresentation.hexString == vector.BlindedElement)

            let server = OPRF.Server(mode: .base, ciphersuite: ciphersuite, privateKey: privateKey, v8CompatibilityMode: v8DraftCompatible)

            var info = Data()
            if vector.Info != nil { info = try Data(hexString: vector.Info!) }

            let evaluate = try server.evaluate(blindedElement: blindedElement, info: info)

            let evaluatedElementTv = try GroupImpl<G>.Element(oprfRepresentation: Data(hexString: vector.EvaluationElement))
            XCTAssert(evaluate.0 == evaluatedElementTv)

            let finalized = try client.finalize(message: input,
                                                info: info,
                                                blind: blind,
                                                evaluatedElement: evaluate.0)

            XCTAssert(finalized.hexString == vector.Output)
            XCTAssert(try server.verifyFinalize(msg: input, output: finalized, info: info))
        }
    }

    func testVerifiableSuite<G: SupportedCurveDetailsImpl>(suite: OPRFSuite, C: G.Type, v8DraftCompatible: Bool, mode: OPRF.Mode) throws {
        print("Testing \(suite.suiteName ?? suite.identifier!) in \(mode) mode.")

        let privateKey = try GroupImpl<G>.Scalar(bytes: Data(hexString: suite.skSm))
        let ciphersuite = OPRF.Ciphersuite(HashToCurveImpl<G>.self)

        for vector in suite.vectors {
            if vector.Batch != 1 {
                continue
            }

            let client = try! OPRF.VerifiableClient(ciphersuite: ciphersuite, v8CompatibilityMode: v8DraftCompatible, mode: mode)
            let blindTestVector = try GroupImpl<G>.Scalar(bytes: Data(hexString: vector.Blind))
            let input = try Data(hexString: vector.Input)

            let (blind, blindedElement) = client.blindMessage(input, blind: blindTestVector)

            XCTAssert(blindTestVector == blind)
            XCTAssert(blindedElement.oprfRepresentation.hexString == vector.BlindedElement)

            let server = try! OPRF.VerifiableServer(ciphersuite: ciphersuite, privateKey: privateKey, v8CompatibilityMode: v8DraftCompatible, mode: mode)
            let proofBlind = try GroupImpl<G>.Scalar(bytes: Data(hexString: vector.Proof!.r))

            var info: Data?
            if (vector.Info?.count ?? 0) > 0 { info = try Data(hexString: vector.Info!) }

            let evaluate = try server.evaluate(blindedElement: blindedElement, info: info, proofScalar: proofBlind)

            let evaluatedElementTv = try GroupImpl<G>.Element(oprfRepresentation: Data(hexString: vector.EvaluationElement))
            XCTAssert(evaluate.0 == evaluatedElementTv)

            let proof_tv = vector.Proof!.proof
            let c_tv = try GroupImpl<G>.Scalar(bytes: Data(hexString: String(proof_tv.prefix(proof_tv.count / 2))))
            let s_tv = try GroupImpl<G>.Scalar(bytes: Data(hexString: String(proof_tv.suffix(proof_tv.count / 2))))
            let proof = DLEQProof(c: c_tv, s: s_tv)

            switch (vector.result) {
            case .some(Result.invalidProof.rawValue): do {
                XCTAssertThrowsError(try client.finalize(message: input,
                                                         info: info,
                                                         blind: blind,
                                                         evaluatedElement: evaluate.0,
                                                         proof: proof,
                                                         publicKey: server.publicKey),
                                     error: OPRF.Errors.invalidProof)
            }
            case .some(Result.invalidOPRFOutput.rawValue): do {
                XCTAssertFalse(try server.verifyFinalize(msg: input, output: Data(hexString: vector.Output), info: info))
            }
            default:
                XCTAssert(c_tv == evaluate.1.c)
                XCTAssert(s_tv == evaluate.1.s)
                let finalized = try client.finalize(message: input,
                                                    info: info,
                                                    blind: blind,
                                                    evaluatedElement: evaluate.0,
                                                    proof: proof,
                                                    publicKey: server.publicKey)

                XCTAssert(finalized.hexString == vector.Output)
                XCTAssert(try server.verifyFinalize(msg: input, output: finalized, info: info))
            }
        }
    }

    func testVectors() throws {
        print("Testing VOPRF Draft8 vectors.")
        try testVectors(filename: "OPRFVectors-VOPRFDraft8", v8DraftCompatible: true)
        print("Testing VOPRF Draft19 vectors.")
        try testVectors(filename: "OPRFVectors-VOPRFDraft19", v8DraftCompatible: false)
        print("Testing VOPRF edge case vectors.")
        try testVectors(filename: "OPRFVectors-edgecases", v8DraftCompatible: false)
    }

    func testVectors(filename: String, v8DraftCompatible: Bool) throws {
        #if CRYPTO_IN_SWIFTPM
        let bundle = Bundle.module
        #else
        let bundle = Bundle(for: type(of: self))
        #endif

        let fileURL = bundle.url(forResource: filename, withExtension: "json")

        let data = try Data(contentsOf: fileURL!)
        let decoder = JSONDecoder()
        let suites = try decoder.decode([OPRFSuite].self, from: data)

        if v8DraftCompatible {
            for suite in suites {
                switch (suite.suiteID, suite.mode) {
                case (OPRF.Ciphersuite(HashToCurveImpl<P256>.self).suiteID, let modeValue): do {
                    try testSuite(suite: suite, C: P256.self, modeValue: modeValue, v8DraftCompatible: v8DraftCompatible)
                }
                case (OPRF.Ciphersuite(HashToCurveImpl<P384>.self).suiteID, let modeValue): do {
                    try testSuite(suite: suite, C: P384.self, modeValue: modeValue, v8DraftCompatible: v8DraftCompatible)
                }
//                case (OPRF.Ciphersuite(HashToCurveImpl<P521>.self).suiteID, let modeValue): do {
//                    try testSuite(suite: suite, C: P521.self, modeValue: modeValue, v8DraftCompatible: v8DraftCompatible)
//                }

                default:
                    print("Unsupported Ciphersuite: \(suite.suiteName ?? suite.identifier!)")
                }
            }
        } else {
            for suite in suites {
                switch (suite.identifier, suite.mode) {
                case (OPRF.Ciphersuite(HashToCurveImpl<P256>.self).stringIdentifier, let modeValue): do {
                    try testSuite(suite: suite, C: P256.self, modeValue: modeValue, v8DraftCompatible: v8DraftCompatible)
                }
                case (OPRF.Ciphersuite(HashToCurveImpl<P384>.self).stringIdentifier, let modeValue): do {
                    try testSuite(suite: suite, C: P384.self, modeValue: modeValue, v8DraftCompatible: v8DraftCompatible)
                }
//                case (OPRF.Ciphersuite(HashToCurveImpl<P521>.self).stringIdentifier, let modeValue): do {
//                    try testSuite(suite: suite, C: P521.self, modeValue: modeValue, v8DraftCompatible: v8DraftCompatible)
//                }

                default:
                    print("Unsupported Ciphersuite: \(suite.suiteName ?? suite.identifier!)")
                }
            }
        }
    }

    func testDistributivity() throws {
        let r = GroupImpl<P256>.Scalar.random

        let a = GroupImpl<P256>.Scalar.random
        let b = GroupImpl<P256>.Scalar.random

        let ab = (a + b)
        let ar = a * r
        let br = b * r

        XCTAssert(ab - b == a)
        XCTAssert(ab - a == b)

        let arbr = (ab) * r

        XCTAssert(arbr - br == ar)
        XCTAssert(arbr - ar == br)
    }

    func testMath() throws {
        let r = GroupImpl<P256>.Scalar.random
        let k = GroupImpl<P256>.Scalar.random
        let c = GroupImpl<P256>.Scalar.random

        let A = GroupImpl<P256>.Element.generator
        let B = k * A

        let m = GroupImpl<P256>.Scalar.random
        let z = k * m

        let t2 = r * A
        let t3 = r * m

        let s = (r - c * k)
        let t2_recontructed = (s * A) + (c * B)
        let t3_reconstructed = ((s * m) + (c * z))

        XCTAssert(t2 == t2_recontructed)
        XCTAssert(t3.rawRepresentation == t3_reconstructed.rawRepresentation)
    }

    func testDLEQProver() throws {
        let k = GroupImpl<P256>.Scalar.random
        let A = GroupImpl<P256>.Element.generator
        let B = k * A

        let C = GroupImpl<P256>.Element.random
        let D = k * C

        let CDs = [(C: C, D: D)]

        let proof = try DLEQ<HashToCurveImpl<P256>>.proveEquivalenceBetween(k: k, A: A, B: B, CDs: CDs, dst: Data(), proofScalar: .random, v8CompatibilityMode: false)

        XCTAssert(try DLEQ<HashToCurveImpl<P256>>.verifyProof(A: A, B: B, CDs: CDs, proof: proof, dst: Data(), v8CompatibilityMode: false))
    }
}
