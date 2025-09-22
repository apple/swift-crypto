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

/// (Verifiable Partly-)Oblivious Pseudorandom Functions
/// https://cfrg.github.io/draft-irtf-cfrg-voprf/draft-irtf-cfrg-voprf.html
@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
enum OPRF {}

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
extension OPRF {
    enum Errors: Error {
        case invalidProof
        case incorrectProofSize
        case invalidModeForInfo
        case incompatibleMode
    }
}

/// Defines the IETF Serializations for OPRFs
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
protocol OPRFGroupElement: GroupElement {
    init(oprfRepresentation: Data) throws
    var oprfRepresentation: Data { get }
}

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, macCatalyst 13.2, visionOS 1.2, *)
extension OPRF {
    static func oprfVersion(v8CompatibilityMode: Bool) -> String {
        if v8CompatibilityMode {
            return "VOPRF08-"
        } else {
            return "OPRFV1-"
        }
    }
    
    /// OPRF Modes
    enum Mode: Int, CaseIterable {
        // Base mode corresponds to an OPRF
        case base = 0
        // Verifiable mode corresponds to a V(erifiable)OPRF
        case verifiable = 1
        // Partially-Oblivious verifiable OPRF
        case partiallyOblivious = 2
    }
    
    /// IETF Ciphersuites defined for OPRFs
    struct Ciphersuite<H2G: HashToGroup> {
        let suiteID: Int
        
        init(_ h2g: H2G.Type) {
            switch h2g.self {
            case is HashToCurveImpl<P256>.Type:
                suiteID = 3
            case is HashToCurveImpl<P384>.Type:
                suiteID = 4
            case is HashToCurveImpl<P521>.Type:
                suiteID = 5
            default:
                fatalError("Unsupported H2G ciphersuite.")
            }
        }
        
        var stringIdentifier: String {
            get {
                switch suiteID {
                case 3:
                    return "P256-SHA256"
                case 4:
                    return "P384-SHA384"
                case 5:
                    return "P521-SHA512"
                default:
                    fatalError("Unsupported H2G ciphersuite.")
                }
            }
        }
    }
    
    internal static func suiteIdentifier<H2G: HashToGroup>(suite: Ciphersuite<H2G>, v8CompatibilityMode: Bool) -> Data {
        if v8CompatibilityMode {
            return I2OSP(value: suite.suiteID, outputByteCount: 2)
        } else {
            return Data("-\(suite.stringIdentifier)".utf8)
        }
    }
    
    internal static func setupContext<H2G: HashToGroup>(mode: Mode, suite: Ciphersuite<H2G>, v8CompatibilityMode: Bool) -> Data {
        return oprfVersion(v8CompatibilityMode: v8CompatibilityMode).data(using: .utf8)!
        + I2OSP(value: mode.rawValue, outputByteCount: 1)
        + suiteIdentifier(suite: suite, v8CompatibilityMode: v8CompatibilityMode)
    }
    
    internal static func composeFinalizeContext<H2G: HashToGroup>(message: Data,
                                                                  info: Data?,
                                                                  unblindedElement: H2G.G.Element,
                                                                  ciphersuite: Ciphersuite<H2G>,
                                                                  mode: Mode,
                                                                  v8CompatibilityMode: Bool) -> Data {
        if v8CompatibilityMode {
            let finalizeCTX = "Finalize-".data(using: .utf8)! + setupContext(mode: mode, suite: ciphersuite, v8CompatibilityMode: v8CompatibilityMode)
            let hashInput = I2OSP(value: message.count, outputByteCount: 2) + message
            + I2OSP(value: info?.count ?? 0, outputByteCount: 2) + (info ?? Data())
            + I2OSP(value: unblindedElement.oprfRepresentation.count, outputByteCount: 2) + unblindedElement.oprfRepresentation
            + I2OSP(value: finalizeCTX.count, outputByteCount: 2) + finalizeCTX
            
            return hashInput
        } else {
            var hashInput = I2OSP(value: message.count, outputByteCount: 2) + message
            
            if mode == .partiallyOblivious {
                hashInput = hashInput + I2OSP(value: info!.count, outputByteCount: 2) + info!
            }
            
            hashInput = hashInput + I2OSP(value: unblindedElement.oprfRepresentation.count, outputByteCount: 2) + unblindedElement.oprfRepresentation + Data("Finalize".utf8)
            return hashInput
        }
    }
}
