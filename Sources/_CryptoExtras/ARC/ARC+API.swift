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

// MARK: - P256 + ARC(P-256)
@available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 2.0, *)
extension P256 {
    /// Anonymous Rate-Limited Credentials (ARC).
    ///
    /// A specialization of keyed-verification anonymous credentials with support for rate limiting.
    ///
    /// - Seealso: [IETF Internet Draft: draft-yun-cfrg-arc-00](https://datatracker.ietf.org/doc/draft-yun-cfrg-arc).
    public enum _ARCV1 {
        internal typealias H2G = HashToCurveImpl<P256>
        internal typealias Ciphersuite = ARC.Ciphersuite<H2G>
        fileprivate typealias Server = ARC.Server<H2G>

        internal static let ciphersuite = Ciphersuite(H2G.self)
    }
}

@available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 2.0, *)
extension P256._ARCV1 {
    /// The server secrets used to issue and verify credentials.
    public struct PrivateKey: Sendable {
        fileprivate var backing: ARC.Server<H2G>

        /// Creates a random private key for ARC(P-256).
        public init() {
            self.backing = ARC.Server(ciphersuite: P256._ARCV1.ciphersuite)
        }

        // The spec does not define a serialization of the private key since, unlike the public key, it is not an
        // interop concern.
        //
        // This initializer expects a concatenation of the binary representations of the private scalars:
        //
        //     struct {
        //       uint8 x0[Ne];
        //       uint8 x1[Ne];
        //       uint8 x2[Ne];
        //       uint8 x0Blinding[Ne];
        //     } ServerPrivateKey;
        //
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            guard rawRepresentation.count == 4 * P256.orderByteCount else {
                throw ARC.Errors.incorrectPrivateKeyDataSize
            }

            var bytes = Data(rawRepresentation)[...]
            let x0 = try  H2G.G.Scalar(bytes: bytes[..<bytes.startIndex.advanced(by: P256.orderByteCount)])
            bytes.removeFirst(P256.orderByteCount)
            let x1 = try  H2G.G.Scalar(bytes: bytes[..<bytes.startIndex.advanced(by: P256.orderByteCount)])
            bytes.removeFirst(P256.orderByteCount)
            let x2 = try  H2G.G.Scalar(bytes: bytes[..<bytes.startIndex.advanced(by: P256.orderByteCount)])
            bytes.removeFirst(P256.orderByteCount)
            let x0Blinding = try  H2G.G.Scalar(bytes: bytes[..<bytes.startIndex.advanced(by: P256.orderByteCount)])
            bytes.removeFirst(P256.orderByteCount)
            assert(bytes.isEmpty)

            self.backing = ARC.Server(ciphersuite: P256._ARCV1.ciphersuite, x0: x0, x1: x1, x2: x2, x0Blinding: x0Blinding)
        }

        // The spec does not define a serialization of the private key since, unlike the public key, it is not an
        // interop concern.
        //
        // This initializer expects a concatenation of the binary representations of the private scalars:
        //
        //     struct {
        //       uint8 x0[Ns];
        //       uint8 x1[Ns];
        //       uint8 x2[Ns];
        //       uint8 x0Blinding[Ns];
        //     } ServerPrivateKey;
        //
        public var rawRepresentation: Data {
            let serializedByteCount = 4 * P256.orderByteCount
            var result = Data(capacity: serializedByteCount)

            result.append(self.backing.serverPrivateKey.x0.rawRepresentation)
            result.append(self.backing.serverPrivateKey.x1.rawRepresentation)
            result.append(self.backing.serverPrivateKey.x2.rawRepresentation)
            result.append(self.backing.serverPrivateKey.x0Blinding.rawRepresentation)
            assert(result.count == serializedByteCount)

            return result
        }

        public var publicKey: P256._ARCV1.PublicKey {
            P256._ARCV1.PublicKey(backing: self.backing.serverPublicKey)
        }
    }

    /// The server public key, used by clients to create anonymous credentials in conjunction with the server.
    public struct PublicKey: Sendable {
        fileprivate var backing: ARC.ServerPublicKey<H2G>

        fileprivate init(backing: ARC.ServerPublicKey<H2G>) {
            self.backing = backing
        }

        fileprivate static var serializedByteCount: Int { 3 * P256.compressedx962PointByteCount }

        // The spec defines this serialization of the public key:
        //
        //     struct {
        //       uint8 X0[Ne];
        //       uint8 X1[Ne];
        //       uint8 X2[Ne];
        //     } ServerPublicKey;
        //
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            guard rawRepresentation.count == Self.serializedByteCount else { throw ARC.Errors.incorrectPublicKeyDataSize }

            var bytes = Data(rawRepresentation)[...]
            let X0 = try H2G.G.Element(oprfRepresentation: bytes[..<bytes.startIndex.advanced(by: P256.compressedx962PointByteCount)])
            bytes.removeFirst(P256.compressedx962PointByteCount)
            let X1 = try H2G.G.Element(oprfRepresentation: bytes[..<bytes.startIndex.advanced(by: P256.compressedx962PointByteCount)])
            bytes.removeFirst(P256.compressedx962PointByteCount)
            let X2 = try H2G.G.Element(oprfRepresentation: bytes[..<bytes.startIndex.advanced(by: P256.compressedx962PointByteCount)])
            bytes.removeFirst(P256.compressedx962PointByteCount)
            assert(bytes.isEmpty)

            self.backing = ARC.ServerPublicKey(X0: X0, X1: X1, X2: X2)
        }

        // The spec defines this serialization of the public key:
        //
        //     struct {
        //       uint8 X0[Ne];
        //       uint8 X1[Ne];
        //       uint8 X2[Ne];
        //     } ServerPublicKey;
        //
        public var rawRepresentation: Data {
            var result = Data(capacity: Self.serializedByteCount)

            result.append(self.backing.X0.oprfRepresentation)
            result.append(self.backing.X1.oprfRepresentation)
            result.append(self.backing.X2.oprfRepresentation)
            assert(result.count == Self.serializedByteCount)

            return result
        }
    }

    /// A credential request, created by the client, to be sent to the server.
    ///
    /// Clients should not create values of this type manually; they should use the prepare method on the public key.
    ///
    /// Servers should reconstruct values of this type from the serialized bytes sent by the client.
    public struct CredentialRequest: Sendable {
        var backing: ARC.CredentialRequest<H2G>

        fileprivate init(backing: ARC.CredentialRequest<H2G>) {
            self.backing = backing
        }

        public init<D: DataProtocol>(rawRepresentation: D) throws {
            self.backing = try ARC.CredentialRequest.deserialize(requestData: rawRepresentation, ciphersuite: P256._ARCV1.ciphersuite)
        }

        public var rawRepresentation: Data {
            self.backing.serialize(ciphersuite: P256._ARCV1.ciphersuite)
        }
    }

    /// A credential request to be sent to the server, and associated client secrets.
    ///
    /// Users cannot create values of this type manually; they are created using the prepare method on the public key.
    public struct Precredential: Sendable {
        /// This backing type binds many things together, including the server commitments, client secrets, credential
        /// request, and presentation limit.
        internal var backing: ARC.Precredential<H2G>

        /// The credential request to be sent to the server.
        public var credentialRequest: CredentialRequest {
            CredentialRequest(backing: self.backing.credentialRequest)
        }
    }

    /// A credential response, created by the server, to be sent to the client.
    ///
    /// Servers should not create values of this type manually; they should use the issue method on the private key.
    ///
    /// Clients should reconstruct values of this type from the serialized bytes sent by the server.
    public struct CredentialResponse: Sendable {
        var backing: ARC.CredentialResponse<H2G>

        fileprivate init(backing: ARC.CredentialResponse<H2G>) {
            self.backing = backing
        }

        public init<D: DataProtocol>(rawRepresentation: D) throws {
            self.backing = try ARC.CredentialResponse.deserialize(responseData: rawRepresentation, ciphersuite: P256._ARCV1.ciphersuite)
        }

        public var rawRepresentation: Data {
            self.backing.serialize(ciphersuite: P256._ARCV1.ciphersuite)
        }
    }


    /// A credential, created by the client using the response from the server.
    ///
    /// Users cannot create values of this type manually; they are created using the issue method on the public key.
    public struct Credential: Sendable {
        var backing: ARC.Credential<H2G>

        fileprivate init(backing: ARC.Credential<H2G>) {
            self.backing = backing
        }
    }

    /// A presentation, created by the client from a credential, to be sent to the server to verify.
    ///
    /// Users cannot create values of this type manually; they are created using the present method on the credential.
    public struct Presentation: Sendable {
        internal var backing: ARC.Presentation<H2G>

        fileprivate init(backing: ARC.Presentation<H2G>) {
            self.backing = backing
        }

        public init<D: DataProtocol>(rawRepresentation: D) throws {
            self.backing = try ARC.Presentation.deserialize(presentationData: rawRepresentation, ciphersuite: P256._ARCV1.ciphersuite)
        }

        public var rawRepresentation: Data {
            self.backing.serialize(ciphersuite: P256._ARCV1.ciphersuite)
        }

        public var tag: Data {
            self.backing.tag.compressedRepresentation
        }
    }
}

@available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 2.0, *)
extension P256._ARCV1.PublicKey {
    internal func prepareCredentialRequest<D: DataProtocol>(
        requestContext: D,
        m1: P256._ARCV1.H2G.G.Scalar,
        r1: P256._ARCV1.H2G.G.Scalar,
        r2: P256._ARCV1.H2G.G.Scalar
    ) throws -> P256._ARCV1.Precredential {
        let precedential = try ARC.Precredential(
            ciphersuite: P256._ARCV1.ciphersuite,
            m1: m1,
            requestContext: Data(requestContext),
            r1: r1,
            r2: r2,
            serverPublicKey: self.backing
        )
        return P256._ARCV1.Precredential(backing: precedential)
    }

    /// Prepare a credential request for a given request context.
    ///
    /// - Parameters:
    ///   - requestContext: Request context, agreed with the server.
    ///
    /// - Returns: A precredential containing the client secrets, and request to be sent to the server.
    public func prepareCredentialRequest<D: DataProtocol>(
        requestContext: D
    ) throws -> P256._ARCV1.Precredential {
        try self.prepareCredentialRequest(
            requestContext: requestContext,
            m1: .random,
            r1: .random,
            r2: .random
        )
    }
}

@available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 2.0, *)
extension P256._ARCV1.PrivateKey {
    internal func issue(
        _ credentialRequest: P256._ARCV1.CredentialRequest,
        b: P256._ARCV1.H2G.G.Scalar
    ) throws -> P256._ARCV1.CredentialResponse {
        let response = try self.backing.respond(credentialRequest: credentialRequest.backing, b: b)
        return P256._ARCV1.CredentialResponse(backing: response)
    }

    /// Generate a credential response from a credential request.
    public func issue(_ credentialRequest: P256._ARCV1.CredentialRequest) throws -> P256._ARCV1.CredentialResponse {
        try self.issue(credentialRequest, b: .random)
    }
}

@available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 2.0, *)
extension P256._ARCV1.PublicKey {
    /// Create a credential from the issuer response.
    public func finalize(
        _ credentialResponse: P256._ARCV1.CredentialResponse,
        for precredential: P256._ARCV1.Precredential
    ) throws -> P256._ARCV1.Credential {
        let credential = try precredential.backing.makeCredential(credentialResponse: credentialResponse.backing)
        return P256._ARCV1.Credential(backing: credential)
    }
}

@available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 2.0, *)
extension P256._ARCV1.Credential {
    internal mutating func makePresentation<D: DataProtocol>(
        context: D,
        presentationLimit: Int,
        fixedNonce: Int?,
        a: P256._ARCV1.H2G.G.Scalar,
        r: P256._ARCV1.H2G.G.Scalar,
        z: P256._ARCV1.H2G.G.Scalar
    ) throws -> (presentation: P256._ARCV1.Presentation, nonce: Int) {
        let (presentation, nonce) = try self.backing.makePresentation(
            presentationContext: Data(context),
            presentationLimit: presentationLimit,
            a: a,
            r: r,
            z: z,
            optionalNonce: fixedNonce
        )
        return (P256._ARCV1.Presentation(backing: presentation), nonce)
    }

    /// Create a presentation to provide to a verifier.
    ///
    /// - Parameters:
    ///   - context: The presentation context agreed with the verifier.
    ///   - presentationLimit: The presentation limit to enforce.
    ///
    /// - Returns: A presentation of this credential.
    ///
    /// - Throws: An error if the presentation limit for this credential has been exceeded.
    public mutating func makePresentation<D: DataProtocol>(
        context: D,
        presentationLimit: Int
    ) throws -> (presentation: P256._ARCV1.Presentation, nonce: Int) {
        try self.makePresentation(
            context: context,
            presentationLimit: presentationLimit,
            fixedNonce: nil,
            a: .random,
            r: .random,
            z: .random
        )
    }
}

@available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 2.0, *)
extension P256._ARCV1.PrivateKey {
    /// Verify a presentation is valid for a given attribute.
    ///
    /// Presentation verification includes checking that:
    /// 1. The presentation is for the expected request context.
    /// 2. The presentation is for the expected presentation context.
    /// 3. The presentation nonce is appropriate for the presentation limit.
    /// 4. The presentation proof is valid.
    ///
    /// - Parameters:
    ///   - presentation: The presentation to verify.
    ///   - requestContext: The expected request context encoded within the presentation.
    ///   - presentationContext: The expected presentation context encoded within the presentation.
    ///   - presentationLimit: The presentation limit to enforce.
    ///   - nonce: The expected nonce encoded within the presentation.
    ///
    /// - Returns: True if the presentation is valid, false otherwise.
    public func verify<D1: DataProtocol, D2: DataProtocol>(
        _ presentation: P256._ARCV1.Presentation,
        requestContext: D1,
        presentationContext: D2,
        presentationLimit: Int,
        nonce: Int
    ) throws -> Bool {
        try self.backing.verify(
            presentation: presentation.backing,
            requestContext: Data(requestContext),
            presentationContext: Data(presentationContext),
            presentationLimit: presentationLimit,
            nonce: nonce
        )
    }
}

// MARK: - P384 + ARC(P-384)
@available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 2.0, *)
@available(*, deprecated, message: "ARC(P-384) has been removed from the IETF draft; use ARC(P-256) instead.")
extension P384 {
    /// Anonymous Rate-Limited Credentials (ARC).
    ///
    /// A specialization of keyed-verification anonymous credentials with support for rate limiting.
    ///
    /// - Seealso: [IETF Internet Draft: draft-yun-cfrg-arc-00](https://datatracker.ietf.org/doc/draft-yun-cfrg-arc).
    public enum _ARCV1 {
        internal typealias H2G = HashToCurveImpl<P384>
        internal typealias Ciphersuite = ARC.Ciphersuite<H2G>
        fileprivate typealias Server = ARC.Server<H2G>

        internal static let ciphersuite = Ciphersuite(H2G.self)
    }
}

@available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 2.0, *)
@available(*, deprecated, message: "ARC(P-384) has been removed from the IETF draft; use ARC(P-256) instead.")
extension P384._ARCV1 {
    /// The server secrets used to issue and verify credentials.
    public struct PrivateKey: Sendable {
        fileprivate var backing: ARC.Server<H2G>

        /// Creates a random private key for ARC(P-384).
        public init() {
            self.backing = ARC.Server(ciphersuite: P384._ARCV1.ciphersuite)
        }

        // The spec does not define a serialization of the private key since, unlike the public key, it is not an
        // interop concern.
        //
        // This initializer expects a concatenation of the binary representations of the private scalars:
        //
        //     struct {
        //       uint8 x0[Ne];
        //       uint8 x1[Ne];
        //       uint8 x2[Ne];
        //       uint8 x0Blinding[Ne];
        //     } ServerPrivateKey;
        //
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            guard rawRepresentation.count == 4 * P384.orderByteCount else {
                throw ARC.Errors.incorrectPrivateKeyDataSize
            }

            var bytes = Data(rawRepresentation)[...]
            let x0 = try  H2G.G.Scalar(bytes: bytes[..<bytes.startIndex.advanced(by: P384.orderByteCount)])
            bytes.removeFirst(P384.orderByteCount)
            let x1 = try  H2G.G.Scalar(bytes: bytes[..<bytes.startIndex.advanced(by: P384.orderByteCount)])
            bytes.removeFirst(P384.orderByteCount)
            let x2 = try  H2G.G.Scalar(bytes: bytes[..<bytes.startIndex.advanced(by: P384.orderByteCount)])
            bytes.removeFirst(P384.orderByteCount)
            let x0Blinding = try  H2G.G.Scalar(bytes: bytes[..<bytes.startIndex.advanced(by: P384.orderByteCount)])
            bytes.removeFirst(P384.orderByteCount)
            assert(bytes.isEmpty)

            self.backing = ARC.Server(ciphersuite: P384._ARCV1.ciphersuite, x0: x0, x1: x1, x2: x2, x0Blinding: x0Blinding)
        }

        // The spec does not define a serialization of the private key since, unlike the public key, it is not an
        // interop concern.
        //
        // This initializer expects a concatenation of the binary representations of the private scalars:
        //
        //     struct {
        //       uint8 x0[Ns];
        //       uint8 x1[Ns];
        //       uint8 x2[Ns];
        //       uint8 x0Blinding[Ns];
        //     } ServerPrivateKey;
        //
        public var rawRepresentation: Data {
            let serializedByteCount = 4 * P384.orderByteCount
            var result = Data(capacity: serializedByteCount)

            result.append(self.backing.serverPrivateKey.x0.rawRepresentation)
            result.append(self.backing.serverPrivateKey.x1.rawRepresentation)
            result.append(self.backing.serverPrivateKey.x2.rawRepresentation)
            result.append(self.backing.serverPrivateKey.x0Blinding.rawRepresentation)
            assert(result.count == serializedByteCount)

            return result
        }

        public var publicKey: P384._ARCV1.PublicKey {
            P384._ARCV1.PublicKey(backing: self.backing.serverPublicKey)
        }
    }

    /// The server public key, used by clients to create anonymous credentials in conjunction with the server.
    public struct PublicKey: Sendable {
        fileprivate var backing: ARC.ServerPublicKey<H2G>

        fileprivate init(backing: ARC.ServerPublicKey<H2G>) {
            self.backing = backing
        }

        fileprivate static var serializedByteCount: Int { 3 * P384.compressedx962PointByteCount }

        // The spec defines this serialization of the public key:
        //
        //     struct {
        //       uint8 X0[Ne];
        //       uint8 X1[Ne];
        //       uint8 X2[Ne];
        //     } ServerPublicKey;
        //
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            guard rawRepresentation.count == Self.serializedByteCount else { throw ARC.Errors.incorrectPublicKeyDataSize }

            var bytes = Data(rawRepresentation)[...]
            let X0 = try H2G.G.Element(oprfRepresentation: bytes[..<bytes.startIndex.advanced(by: P384.compressedx962PointByteCount)])
            bytes.removeFirst(P384.compressedx962PointByteCount)
            let X1 = try H2G.G.Element(oprfRepresentation: bytes[..<bytes.startIndex.advanced(by: P384.compressedx962PointByteCount)])
            bytes.removeFirst(P384.compressedx962PointByteCount)
            let X2 = try H2G.G.Element(oprfRepresentation: bytes[..<bytes.startIndex.advanced(by: P384.compressedx962PointByteCount)])
            bytes.removeFirst(P384.compressedx962PointByteCount)
            assert(bytes.isEmpty)

            self.backing = ARC.ServerPublicKey(X0: X0, X1: X1, X2: X2)
        }

        // The spec defines this serialization of the public key:
        //
        //     struct {
        //       uint8 X0[Ne];
        //       uint8 X1[Ne];
        //       uint8 X2[Ne];
        //     } ServerPublicKey;
        //
        public var rawRepresentation: Data {
            var result = Data(capacity: Self.serializedByteCount)

            result.append(self.backing.X0.oprfRepresentation)
            result.append(self.backing.X1.oprfRepresentation)
            result.append(self.backing.X2.oprfRepresentation)
            assert(result.count == Self.serializedByteCount)

            return result
        }
    }

    /// A credential request, created by the client, to be sent to the server.
    ///
    /// Clients should not create values of this type manually; they should use the prepare method on the public key.
    ///
    /// Servers should reconstruct values of this type from the serialized bytes sent by the client.
    public struct CredentialRequest: Sendable {
        var backing: ARC.CredentialRequest<H2G>

        fileprivate init(backing: ARC.CredentialRequest<H2G>) {
            self.backing = backing
        }

        public init<D: DataProtocol>(rawRepresentation: D) throws {
            self.backing = try ARC.CredentialRequest.deserialize(requestData: rawRepresentation, ciphersuite: P384._ARCV1.ciphersuite)
        }

        public var rawRepresentation: Data {
            self.backing.serialize(ciphersuite: P384._ARCV1.ciphersuite)
        }
    }

    /// A credential request to be sent to the server, and associated client secrets.
    ///
    /// Users cannot create values of this type manually; they are created using the prepare method on the public key.
    public struct Precredential: Sendable {
        /// This backing type binds many things together, including the server commitments, client secrets, credential
        /// request, and presentation limit.
        internal var backing: ARC.Precredential<H2G>

        /// The credential request to be sent to the server.
        public var credentialRequest: CredentialRequest {
            CredentialRequest(backing: self.backing.credentialRequest)
        }
    }

    /// A credential response, created by the server, to be sent to the client.
    ///
    /// Servers should not create values of this type manually; they should use the issue method on the private key.
    ///
    /// Clients should reconstruct values of this type from the serialized bytes sent by the server.
    public struct CredentialResponse: Sendable {
        var backing: ARC.CredentialResponse<H2G>

        fileprivate init(backing: ARC.CredentialResponse<H2G>) {
            self.backing = backing
        }

        public init<D: DataProtocol>(rawRepresentation: D) throws {
            self.backing = try ARC.CredentialResponse.deserialize(responseData: rawRepresentation, ciphersuite: P384._ARCV1.ciphersuite)
        }

        public var rawRepresentation: Data {
            self.backing.serialize(ciphersuite: P384._ARCV1.ciphersuite)
        }
    }


    /// A credential, created by the client using the response from the server.
    ///
    /// Users cannot create values of this type manually; they are created using the issue method on the public key.
    public struct Credential: Sendable {
        var backing: ARC.Credential<H2G>

        fileprivate init(backing: ARC.Credential<H2G>) {
            self.backing = backing
        }
    }

    /// A presentation, created by the client from a credential, to be sent to the server to verify.
    ///
    /// Users cannot create values of this type manually; they are created using the present method on the credential.
    public struct Presentation: Sendable {
        internal var backing: ARC.Presentation<H2G>

        fileprivate init(backing: ARC.Presentation<H2G>) {
            self.backing = backing
        }

        public init<D: DataProtocol>(rawRepresentation: D) throws {
            self.backing = try ARC.Presentation.deserialize(presentationData: rawRepresentation, ciphersuite: P384._ARCV1.ciphersuite)
        }

        public var rawRepresentation: Data {
            self.backing.serialize(ciphersuite: P384._ARCV1.ciphersuite)
        }

        public var tag: Data {
            self.backing.tag.compressedRepresentation
        }
    }
}

@available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 2.0, *)
@available(*, deprecated, message: "ARC(P-384) has been removed from the IETF draft; use ARC(P-256) instead.")
extension P384._ARCV1.PublicKey {
    internal func prepareCredentialRequest<D: DataProtocol>(
        requestContext: D,
        m1: P384._ARCV1.H2G.G.Scalar,
        r1: P384._ARCV1.H2G.G.Scalar,
        r2: P384._ARCV1.H2G.G.Scalar
    ) throws -> P384._ARCV1.Precredential {
        let precedential = try ARC.Precredential(
            ciphersuite: P384._ARCV1.ciphersuite,
            m1: m1,
            requestContext: Data(requestContext),
            r1: r1,
            r2: r2,
            serverPublicKey: self.backing
        )
        return P384._ARCV1.Precredential(backing: precedential)
    }

    /// Prepare a credential request for a given request context.
    ///
    /// - Parameters:
    ///   - requestContext: Request context, agreed with the server.
    ///
    /// - Returns: A precredential containing the client secrets, and request to be sent to the server.
    public func prepareCredentialRequest<D: DataProtocol>(
        requestContext: D
    ) throws -> P384._ARCV1.Precredential {
        try self.prepareCredentialRequest(
            requestContext: requestContext,
            m1: .random,
            r1: .random,
            r2: .random
        )
    }
}

@available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 2.0, *)
@available(*, deprecated, message: "ARC(P-384) has been removed from the IETF draft; use ARC(P-256) instead.")
extension P384._ARCV1.PrivateKey {
    internal func issue(
        _ credentialRequest: P384._ARCV1.CredentialRequest,
        b: P384._ARCV1.H2G.G.Scalar
    ) throws -> P384._ARCV1.CredentialResponse {
        let response = try self.backing.respond(credentialRequest: credentialRequest.backing, b: b)
        return P384._ARCV1.CredentialResponse(backing: response)
    }

    /// Generate a credential response from a credential request.
    public func issue(_ credentialRequest: P384._ARCV1.CredentialRequest) throws -> P384._ARCV1.CredentialResponse {
        try self.issue(credentialRequest, b: .random)
    }
}

@available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 2.0, *)
@available(*, deprecated, message: "ARC(P-384) has been removed from the IETF draft; use ARC(P-256) instead.")
extension P384._ARCV1.PublicKey {
    /// Create a credential from the issuer response.
    public func finalize(
        _ credentialResponse: P384._ARCV1.CredentialResponse,
        for precredential: P384._ARCV1.Precredential
    ) throws -> P384._ARCV1.Credential {
        let credential = try precredential.backing.makeCredential(credentialResponse: credentialResponse.backing)
        return P384._ARCV1.Credential(backing: credential)
    }
}

@available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 2.0, *)
@available(*, deprecated, message: "ARC(P-384) has been removed from the IETF draft; use ARC(P-256) instead.")
extension P384._ARCV1.Credential {
    internal mutating func makePresentation<D: DataProtocol>(
        context: D,
        presentationLimit: Int,
        fixedNonce: Int?,
        a: P384._ARCV1.H2G.G.Scalar,
        r: P384._ARCV1.H2G.G.Scalar,
        z: P384._ARCV1.H2G.G.Scalar
    ) throws -> (presentation: P384._ARCV1.Presentation, nonce: Int) {
        let (presentation, nonce) = try self.backing.makePresentation(
            presentationContext: Data(context),
            presentationLimit: presentationLimit,
            a: a,
            r: r,
            z: z,
            optionalNonce: fixedNonce
        )
        return (P384._ARCV1.Presentation(backing: presentation), nonce)
    }

    /// Create a presentation to provide to a verifier.
    ///
    /// - Parameters:
    ///   - context: The presentation context agreed with the verifier.
    ///   - presentationLimit: The presentation limit to enforce.
    ///
    /// - Returns: A presentation of this credential.
    ///
    /// - Throws: An error if the presentation limit for this credential has been exceeded.
    public mutating func makePresentation<D: DataProtocol>(
        context: D,
        presentationLimit: Int
    ) throws -> (presentation: P384._ARCV1.Presentation, nonce: Int) {
        try self.makePresentation(
            context: context,
            presentationLimit: presentationLimit,
            fixedNonce: nil,
            a: .random,
            r: .random,
            z: .random
        )
    }
}

@available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 2.0, *)
@available(*, deprecated, message: "ARC(P-384) has been removed from the IETF draft; use ARC(P-256) instead.")
extension P384._ARCV1.PrivateKey {
    /// Verify a presentation is valid for a given attribute.
    ///
    /// Presentation verification includes checking that:
    /// 1. The presentation is for the expected request context.
    /// 2. The presentation is for the expected presentation context.
    /// 3. The presentation nonce is appropriate for the presentation limit.
    /// 4. The presentation proof is valid.
    ///
    /// - Parameters:
    ///   - presentation: The presentation to verify.
    ///   - requestContext: The expected request context encoded within the presentation.
    ///   - presentationContext: The expected presentation context encoded within the presentation.
    ///   - presentationLimit: The presentation limit to enforce.
    ///   - nonce: The expected nonce encoded within the presentation.
    ///
    /// - Returns: True if the presentation is valid, false otherwise.
    public func verify<D1: DataProtocol, D2: DataProtocol>(
        _ presentation: P384._ARCV1.Presentation,
        requestContext: D1,
        presentationContext: D2,
        presentationLimit: Int,
        nonce: Int
    ) throws -> Bool {
        try self.backing.verify(
            presentation: presentation.backing,
            requestContext: Data(requestContext),
            presentationContext: Data(presentationContext),
            presentationLimit: presentationLimit,
            nonce: nonce
        )
    }
}
