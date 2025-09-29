//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
@_implementationOnly import CCryptoBoringSSL
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
protocol BoringSSLBackedMLDSAPrivateKey: Sendable {
    associatedtype AssociatedPublicKey: BoringSSLBackedMLDSAPublicKey

    init() throws

    init<D: DataProtocol>(seedRepresentation: D) throws

    func signature<D: DataProtocol>(for data: D) throws -> Data

    func signature<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data

    var publicKey: AssociatedPublicKey { get }

    var seedRepresentation: Data { get }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
protocol BoringSSLBackedMLDSAPublicKey: Sendable {
    init<D: DataProtocol>(rawRepresentation: D) throws

    func isValidSignature<S: DataProtocol, D: DataProtocol>(_: S, for data: D) -> Bool

    func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(_: S, for data: D, context: C) -> Bool

    var rawRepresentation: Data { get }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
protocol BoringSSLBackedMLDSAParameters {
    associatedtype BackingPrivateKey: BoringSSLBackedMLDSAPrivateKey
    where BackingPrivateKey.AssociatedPublicKey == BackingPublicKey
    associatedtype BackingPublicKey: BoringSSLBackedMLDSAPublicKey
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLDSA65: BoringSSLBackedMLDSAParameters {
    typealias BackingPrivateKey = MLDSA65.InternalPrivateKey
    typealias BackingPublicKey = MLDSA65.InternalPublicKey
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLDSA87: BoringSSLBackedMLDSAParameters {
    typealias BackingPrivateKey = MLDSA87.InternalPrivateKey
    typealias BackingPublicKey = MLDSA87.InternalPublicKey
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLDSA65.InternalPrivateKey: BoringSSLBackedMLDSAPrivateKey {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLDSA65.InternalPublicKey: BoringSSLBackedMLDSAPublicKey {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLDSA87.InternalPrivateKey: BoringSSLBackedMLDSAPrivateKey {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLDSA87.InternalPublicKey: BoringSSLBackedMLDSAPublicKey {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct OpenSSLMLDSAPrivateKeyImpl<Parameters: BoringSSLBackedMLDSAParameters> {
    private var backing: Parameters.BackingPrivateKey
    private let publicKeyHash: SHA3_256Digest

    init() throws {
        self.backing = try .init()
        self.publicKeyHash = SHA3_256.hash(data: self.backing.publicKey.rawRepresentation)
    }

    init<D: DataProtocol>(seedRepresentation: D, publicKeyRawRepresentation: Data?) throws {
        let publicKeyHash = publicKeyRawRepresentation.map {
            SHA3_256.hash(data: $0)
        }
        self = try Self(seedRepresentation: seedRepresentation, publicKeyHash: publicKeyHash)
    }

    init<D: DataProtocol>(seedRepresentation: D, publicKeyHash: SHA3_256Digest?) throws {
        self.backing = try .init(seedRepresentation: seedRepresentation)
        let generatedHash = SHA3_256.hash(data: self.backing.publicKey.rawRepresentation)

        if let publicKeyHash, generatedHash != publicKeyHash {
            throw CryptoKitError.unwrapFailure
        }

        self.publicKeyHash = generatedHash
    }

    func signature<D: DataProtocol>(for data: D) throws -> Data {
        try self.backing.signature(for: data)
    }

    func signature<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data {
        try self.backing.signature(for: data, context: context)
    }

    var publicKey: OpenSSLMLDSAPublicKeyImpl<Parameters> {
        .init(backing: self.backing.publicKey)
    }

    var seedRepresentation: Data {
        self.backing.seedRepresentation
    }

    var integrityCheckedRepresentation: Data {
        var representation = self.seedRepresentation
        representation.reserveCapacity(SHA3_256Digest.byteCount)
        self.publicKeyHash.withUnsafeBytes {
            representation.append(contentsOf: $0)
        }
        return representation
    }

    static var seedSize: Int {
        MLDSA.seedByteCount
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct OpenSSLMLDSAPublicKeyImpl<Parameters: BoringSSLBackedMLDSAParameters> {
    private var backing: Parameters.BackingPublicKey

    fileprivate init(backing: Parameters.BackingPublicKey) {
        self.backing = backing
    }

    init<D: DataProtocol>(rawRepresentation: D) throws {
        self.backing = try .init(rawRepresentation: rawRepresentation)
    }

    func isValidSignature<S: DataProtocol, D: DataProtocol>(
        _ signature: S,
        for data: D
    ) -> Bool {
        self.backing.isValidSignature(signature, for: data)
    }

    func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(
        _ signature: S,
        for data: D,
        context: C
    ) -> Bool {
        self.backing.isValidSignature(signature, for: data, context: context)
    }

    var rawRepresentation: Data {
        self.backing.rawRepresentation
    }
}

#endif  // CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
