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

// MARK: - P384 + VPORF (P384-SHA384)
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P384 {
    /// A mechanism to compute the output of a pseudorandom without the client learning the secret or the server
    /// learning the input using the P384-SHA384 Verifiable Oblivious Pseudorandom Function (VOPRF).
    ///
    /// - Seealso: [RFC 9497: VOPRF Protocol](https://www.rfc-editor.org/rfc/rfc9497.html#name-voprf-protocol).
    /// - Seealso: [RFC 9497: OPRF(P-384, SHA-384)](https://www.rfc-editor.org/rfc/rfc9497.html#name-oprfp-384-sha-384).
    @available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 2.0, *)
    public enum _VOPRF {
        typealias H2G = HashToCurveImpl<P384>
        typealias Ciphersuite = OPRF.Ciphersuite<H2G>
        typealias Client = OPRF.VerifiableClient<H2G>
        typealias Server = OPRF.VerifiableServer<H2G>

        static var ciphersuite: Ciphersuite { Ciphersuite(H2G.self) }

        /// A P-384 public key used to blind inputs and finalize blinded elements.
        public struct PublicKey {
            fileprivate typealias BackingPublicKey = P384.Signing.PublicKey
            fileprivate var backingKey: BackingPublicKey
            fileprivate var backingPoint: H2G.G.Element
            fileprivate static var client: Client { try! Client(ciphersuite: P384._VOPRF.ciphersuite, mode: .verifiable) }

            fileprivate init(backingKey: BackingPublicKey) {
                self.backingKey = backingKey
                self.backingPoint = try! H2G.G.Element(oprfRepresentation: backingKey.compressedRepresentation)
            }

            /// Creates a P-384 public key for VOPRF(P-384, SHA-384) from a collection of bytes.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A raw representation of the key as a collection of contiguous bytes.
            public init<D: ContiguousBytes>(rawRepresentation: D) throws {
                self.init(backingKey: try BackingPublicKey(rawRepresentation: rawRepresentation))
            }

            /// Creates a P-384 public key for VOPRF(P-384, SHA-384) from a compact representation of the key.
            ///
            /// - Parameters:
            ///   - compactRepresentation: A compact representation of the key as a collection of contiguous bytes.
            public init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws {
                self.init(backingKey: try BackingPublicKey(compactRepresentation: compactRepresentation))
            }

            /// Creates a P-384 public key for VOPRF(P-384, SHA-384) from an ANSI x9.63 representation.
            ///
            /// - Parameters:
            ///   - x963Representation: An ANSI x9.63 representation of the key as collection of contiguous bytes.
            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                self.init(backingKey: try BackingPublicKey(x963Representation: x963Representation))
            }

            /// Creates a P-384 public key for VOPRF(P-384, SHA-384) from a compressed representation of the key.
            ///
            /// - Parameters:
            ///   - compressedRepresentation: A compressed representation of the key as a collection of contiguous bytes.
            public init<Bytes: ContiguousBytes>(compressedRepresentation: Bytes) throws {
                self.init(backingKey: try BackingPublicKey(compressedRepresentation: compressedRepresentation))
            }

            /// Creates a P-384 public key for VOPRF(P-384, SHA-384) from a Privacy-Enhanced Mail (PEM) representation.
            ///
            /// - Parameters:
            ///   - pemRepresentation: A PEM representation of the key.
            public init(pemRepresentation: String) throws {
                self.init(backingKey: try BackingPublicKey(pemRepresentation: pemRepresentation))
            }

            /// Creates a P-384 public key for VOPRF(P-384, SHA-384) from a Distinguished Encoding Rules (DER) encoded
            /// representation.
            ///
            /// - Parameters:
            ///   - derRepresentation: A DER-encoded representation of the key.
            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws where Bytes.Element == UInt8 {
                self.init(backingKey: try BackingPublicKey(derRepresentation: derRepresentation))
            }

            /// A compact representation of the public key.
            public var compactRepresentation: Data? { self.backingKey.compactRepresentation }

            /// A full representation of the public key.
            public var rawRepresentation: Data { self.backingKey.rawRepresentation }

            /// An ANSI x9.63 representation of the public key.
            public var x963Representation: Data { self.backingKey.x963Representation }

            /// A compressed representation of the public key.
            public var compressedRepresentation: Data { self.backingKey.compressedRepresentation }

            /// A Distinguished Encoding Rules (DER) encoded representation of the public key.
            public var derRepresentation: Data { self.backingKey.derRepresentation }

            /// A Privacy-Enhanced Mail (PEM) representation of the public key.
            public var pemRepresentation: String { self.backingKey.pemRepresentation }

            /// An RFC 9497 OPRF representation of the public key.
            public var oprfRepresentation: Data { self.backingPoint.oprfRepresentation }
        }

        /// A P-384 public key used to evaluate blinded inputs.
        public struct PrivateKey {
            fileprivate typealias BackingPrivateKey = P384.Signing.PrivateKey
            fileprivate var backingKey: BackingPrivateKey
            fileprivate var backingScalar: H2G.G.Scalar
            fileprivate var server: Server

            fileprivate init(backingKey: BackingPrivateKey) {
                self.backingKey = backingKey
                self.backingScalar = try! H2G.G.Scalar(bytes: backingKey.rawRepresentation)
                self.server = try! Server(ciphersuite: P384._VOPRF.ciphersuite, privateKey: self.backingScalar, mode: .verifiable)
            }

            /// Creates a random P-384 private key for VOPRF(P-384, SHA-384).
            ///
            /// Keys that use a compact point encoding enable shorter public keys, but aren’t
            /// compliant with FIPS certification. If your app requires FIPS certification,
            /// create a key with ``init(rawRepresentation:)``.
            ///
            /// - Parameters:
            ///   - compactRepresentable: Determines whether to create a key that supports compact point encoding.
            public init(compactRepresentable: Bool = true) {
                self.init(backingKey: BackingPrivateKey(compactRepresentable: compactRepresentable))
            }

            /// Creates a P-384 private key for VOPRF(P-384, SHA-384) from an ANSI x9.63 representation.
            ///
            /// - Parameters:
            ///   - x963Representation: An ANSI x9.63 representation of the key.
            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                self.init(backingKey: try BackingPrivateKey(x963Representation: x963Representation))
            }

            /// Creates a P-384 private key for VOPRF(P-384, SHA-384) from a collection of bytes.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A raw representation of the key as a collection of
            /// contiguous bytes.
            public init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws {
                self.init(backingKey: try BackingPrivateKey(rawRepresentation: rawRepresentation))
            }

            /// Creates a P-384 private key for VOPRF(P-384, SHA-384) from a Privacy-Enhanced Mail PEM) representation.
            ///
            /// - Parameters:
            ///   - pemRepresentation: A PEM representation of the key.
            public init(pemRepresentation: String) throws {
                self.init(backingKey: try BackingPrivateKey(pemRepresentation: pemRepresentation))
            }

            /// Creates a P-384 private key for VOPRF(P-384, SHA-384) from a Distinguished Encoding Rules (DER) encoded
            /// representation.
            ///
            /// - Parameters:
            ///   - derRepresentation: A DER-encoded representation of the key.
            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws where Bytes.Element == UInt8 {
                self.init(backingKey: try BackingPrivateKey(derRepresentation: derRepresentation))
            }

            /// The corresponding public key.
            public var publicKey: P384._VOPRF.PublicKey {
                PublicKey(backingKey: self.backingKey.publicKey)
            }

            /// A data representation of the private key.
            public var rawRepresentation: Data { self.backingKey.rawRepresentation }

            /// An ANSI x9.63 representation of the private key.
            public var x963Representation: Data { self.backingKey.x963Representation }

            /// A Distinguished Encoding Rules (DER) encoded representation of the private key.
            public var derRepresentation: Data {
                self.backingKey.derRepresentation
            }

            /// A Privacy-Enhanced Mail (PEM) representation of the private key.
            public var pemRepresentation: String {
                self.backingKey.pemRepresentation
            }
        }
    }
}

@available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 2.0, *)
extension P384._VOPRF {
    /// A blinding value, used to blind an input.
    ///
    /// Users cannot not create values of this type manually; it is created and returned by the blind operation.
    public struct Blind {
        fileprivate var backing: H2G.G.Scalar

        fileprivate init(backing: H2G.G.Scalar) {
            self.backing = backing
        }
    }

    /// A blinded element, the result of blinding an input.
    ///
    /// Clients should not create values of this type manually; they are created and returned by the blind operation.
    ///
    /// Servers should reconstruct values of this type from the serialized blinded element bytes sent by the client.
    public struct BlindedElement {
        fileprivate var backing: H2G.G.Element

        fileprivate init(backing: H2G.G.Element) {
            self.backing = backing
        }

        /// Construct a blinded element from its OPRF representation.
        ///
        /// Clients should not create values of this type manually; they are created and returned by the blind operation.
        ///
        /// Servers should reconstruct values of this type from the serialized blinded element bytes sent by the client.
        public init<D: DataProtocol>(oprfRepresentation: D) throws {
            self.init(backing: try H2G.G.Element(oprfRepresentation: Data(oprfRepresentation)))
        }

        /// The OPRF representation of the blinded element.
        public var oprfRepresentation: Data { self.backing.oprfRepresentation }
    }

    /// A blinded element and its blind for unblinding.
    ///
    /// Users cannot create values of this type manually; it is created and returned by the blind operation.
    public struct BlindedInput {
        var input: Data
        var blind: Blind

        /// The element representing the blinded input to be sent to the server.
        public var blindedElement: BlindedElement
    }

    /// An evaluated element, the result of the blind evaluate operation.
    ///
    /// Users cannot create values of this type manually; it is created and returned by the evaluate operation.
    public struct EvaluatedElement {
        static var serializedByteCount: Int { P384.compressedx962PointByteCount }

        fileprivate var backing: H2G.G.Element

        fileprivate init(backing: H2G.G.Element) {
            self.backing = backing
        }

        internal init<D: DataProtocol>(oprfRepresentation: D) throws {
            self.init(backing: try H2G.G.Element(oprfRepresentation: Data(oprfRepresentation)))
        }

        /// The OPRF representation of the evaluated element to be sent to the client.
        public var oprfRepresentation: Data { self.backing.oprfRepresentation }
    }

    /// A proof that the evaluated element was computed using the agreed key pair.
    ///
    /// Users cannot create values of this type manually; it is created and returned by the evaluate operation.
    public struct Proof {
        static var serializedByteCount: Int { P384.orderByteCount * 2 }
        fileprivate var backing: DLEQProof<H2G.G.Scalar>

        fileprivate init(backing: DLEQProof<H2G.G.Scalar>) {
            self.backing = backing
        }

        internal init<D: DataProtocol>(rawRepresentation: D) throws {
            guard rawRepresentation.count == Self.serializedByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            var remainingBytes = rawRepresentation[...]

            let challengeBytes = remainingBytes.prefix(P384.orderByteCount)
            remainingBytes = remainingBytes.dropFirst(P384.orderByteCount)

            let responseBytes = remainingBytes.prefix(P384.orderByteCount)
            remainingBytes = remainingBytes.dropFirst(P384.orderByteCount)

            precondition(remainingBytes.isEmpty)

            let challenge = try H2G.G.Scalar(bytes: Data(challengeBytes))
            let response = try H2G.G.Scalar(bytes: Data(responseBytes))
            self.init(backing: DLEQProof<H2G.G.Scalar>(c: challenge, s: response))
        }

        /// A serialized representation of the proof to send to the client.
        public var rawRepresentation: Data {
            var result = Data(capacity: Self.serializedByteCount)
            result.append(self.backing.c.rawRepresentation)
            result.append(self.backing.s.rawRepresentation)
            return result
        }
    }

    /// The result of blind evaluation: the evaluated element and corresponding proof.
    ///
    /// Servers should not create values of this type manually; they are created and returned by the evaluate operation.
    ///
    /// Clients should reconstruct values of this type from the serialized blind evaluation bytes sent by the server.
    public struct BlindEvaluation {
        static var serializedByteCount: Int { EvaluatedElement.serializedByteCount + Proof.serializedByteCount }

        /// The evaluated element.
        public private(set) var evaluatedElement: EvaluatedElement

        /// The proof.
        public private(set) var proof: Proof

        fileprivate init(evaluatedElement: EvaluatedElement, proof: Proof) {
            self.evaluatedElement = evaluatedElement
            self.proof = proof
        }

        /// Construct a blind evaluation from its serialized representation.
        ///
        /// Servers should not create values of this type manually; they are created and returned by the evaluate operation.
        ///
        /// Clients should reconstruct values of this type from the serialized blind evaluation bytes sent by the server.
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            guard rawRepresentation.count == Self.serializedByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }
            
            var remainingBytes = rawRepresentation[...]

            let evaluatedElementBytes = remainingBytes.prefix(EvaluatedElement.serializedByteCount)
            remainingBytes = remainingBytes.dropFirst(EvaluatedElement.serializedByteCount)

            let proofBytes = remainingBytes.prefix(Proof.serializedByteCount)
            remainingBytes = remainingBytes.dropFirst(Proof.serializedByteCount)

            precondition(remainingBytes.isEmpty)

            let evaluatedElement = try EvaluatedElement(oprfRepresentation: evaluatedElementBytes)
            let proof = try Proof(rawRepresentation: proofBytes)
            self.init(evaluatedElement: evaluatedElement, proof: proof)
        }

        /// A serialized representation of the blind evaluation to send to the client.
        public var rawRepresentation: Data {
            var result = Data(capacity: Self.serializedByteCount)
            result.append(self.evaluatedElement.oprfRepresentation)
            result.append(self.proof.rawRepresentation)
            return result
        }
    }
}

@available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 2.0, *)
extension P384._VOPRF.PublicKey {
    internal func blind<D: DataProtocol>(_ input: D, with fixedBlind: P384._VOPRF.H2G.G.Scalar) throws -> P384._VOPRF.BlindedInput {
        let input = Data(input)
        let (blind, blindedElement) = Self.client.blindMessage(input, blind: fixedBlind)
        return P384._VOPRF.BlindedInput(
            input: input,
            blind: P384._VOPRF.Blind(backing: blind),
            blindedElement: P384._VOPRF.BlindedElement(backing: blindedElement)
        )
    }

    /// Blind an input to be evaluated by the server using the VOPRF protocol.
    ///
    /// - Parameter input: The input to blind.
    /// - Returns: The blinded input, and its blind for unblinding.
    ///
    /// - Seealso: [RFC 9497: VOPRF Protocol](https://www.rfc-editor.org/rfc/rfc9497.html#name-voprf-protocol).
    public func blind<D: DataProtocol>(_ input: D) throws -> P384._VOPRF.BlindedInput {
        try self.blind(input, with: .random)
    }

    /// Compute the output of the VOPRF by verifying the server proof, and unblinding and hashing the evaluated element.
    /// 
    /// - Parameter blindedInput: The blinded input from the blind operation, computed earlier by the client.
    /// - Parameter blindEvaluation: The blind evaluation from the evaluate operation, received from the server.
    /// - Returns: The PRF output.
    ///
    /// - Seealso: [RFC 9497: VOPRF Protocol](https://www.rfc-editor.org/rfc/rfc9497.html#name-voprf-protocol).
    public func finalize(_ blindedInput: P384._VOPRF.BlindedInput, using blindEvaluation: P384._VOPRF.BlindEvaluation) throws -> Data {
        try Self.client.finalize(
            message: blindedInput.input,
            info: nil,
            blind: blindedInput.blind.backing,
            evaluatedElement: blindEvaluation.evaluatedElement.backing,
            proof: blindEvaluation.proof.backing,
            publicKey: self.backingPoint
        )
    }
}

@available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 2.0, *)
extension P384._VOPRF.PrivateKey {
    static var hashToGroupDST: Data {
        Data("HashToGroup-".utf8) + OPRF.setupContext(mode: .verifiable, suite: P384._VOPRF.ciphersuite, v8CompatibilityMode: false)
    }

    internal func evaluate(_ blindedElement: P384._VOPRF.BlindedElement, using fixedProofScalar: P384._VOPRF.H2G.G.Scalar) throws -> P384._VOPRF.BlindEvaluation {
        let (evaluatedElement, proof) = try self.server.evaluate(blindedElement: blindedElement.backing, proofScalar: fixedProofScalar)
        return P384._VOPRF.BlindEvaluation(
            evaluatedElement: P384._VOPRF.EvaluatedElement(backing: evaluatedElement),
            proof: P384._VOPRF.Proof(backing: proof)
        )
    }

    /// Compute the evaluated element and associated proof for verification by the client.
    ///
    /// - Parameter blindedElement: The blinded element from the blind operation, received from the client.
    /// - Returns: The blind evaluation to be sent to the client.
    ///
    /// - Seealso: [RFC 9497: VOPRF Protocol](https://www.rfc-editor.org/rfc/rfc9497.html#name-voprf-protocol).
    public func evaluate(_ blindedElement: P384._VOPRF.BlindedElement) throws -> P384._VOPRF.BlindEvaluation {
        try self.evaluate(blindedElement, using: .random)
    }

    /// Compute the PRF without blinding or proof.
    ///
    /// - Parameter input: The input message for which to compute the PRF.
    /// - Returns: The computed PRF, the same as the VOPRF, without the blinding or proof.
    ///
    /// - Seealso: [RFC 9497: VOPRF Protocol - Evaluate]( https://cfrg.github.io/draft-irtf-cfrg-voprf/draft-irtf-cfrg-voprf.html#section-3.3.2-7).
    public func evaluate<D: DataProtocol>(_ input: D) throws -> Data {
        let inputElement = P384._VOPRF.H2G.hashToGroup(
            Data(input),
            domainSeparationString: Self.hashToGroupDST
        )
        let evaluatedElement = self.backingScalar * inputElement
        let finalizeContext = OPRF.composeFinalizeContext(
            message: Data(input),
            info: nil,
            unblindedElement: evaluatedElement,
            ciphersuite: P384._VOPRF.ciphersuite,
            mode: .verifiable,
            v8CompatibilityMode: false
        )
        return Data(P384._VOPRF.H2G.H.hash(data: finalizeContext))
    }
}
