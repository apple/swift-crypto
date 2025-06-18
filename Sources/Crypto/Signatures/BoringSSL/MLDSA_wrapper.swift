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
protocol BoringSSLBackedMLDSAPrivateKey {
    associatedtype AssociatedPublicKey: BoringSSLBackedMLDSAPublicKey

    init() throws

    init<D: DataProtocol>(seedRepresentation: D) throws

    func signature<D: DataProtocol>(for data: D) throws -> Data

    func signature<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data

    func signature(forPrehashedMessageRepresentative mu: some DataProtocol) throws -> Data

    var publicKey: AssociatedPublicKey { get }

    var seedRepresentation: Data { get }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
protocol BoringSSLBackedMLDSAPublicKey {
    init<D: DataProtocol>(rawRepresentation: D) throws

    func isValidSignature<S: DataProtocol, D: DataProtocol>(_: S, for data: D) -> Bool

    func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(_: S, for data: D, context: C) -> Bool

    var rawRepresentation: Data { get }

    func prehash<D: DataProtocol>(for data: D) throws -> Data

    func prehash<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data
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

    init() throws {
        self.backing = try .init()
    }

    init<D: DataProtocol>(seedRepresentation: D, publicKey: OpenSSLMLDSAPublicKeyImpl<Parameters>?) throws {
        precondition(publicKey == nil)
        self.backing = try .init(seedRepresentation: seedRepresentation)
    }

    init<D: DataProtocol>(integrityCheckedRepresentation: D) throws {
        fatalError()
    }

    func signature<D: DataProtocol>(for data: D) throws -> Data {
        try self.backing.signature(for: data)
    }

    func signature<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data {
        try self.backing.signature(for: data, context: context)
    }

    func signature_boring(forPrehashedMessageRepresentative mu: some DataProtocol) throws -> Data {
        try self.backing.signature(forPrehashedMessageRepresentative: mu)
    }

    var publicKey: OpenSSLMLDSAPublicKeyImpl<Parameters> {
        .init(backing: self.backing.publicKey)
    }

    var seedRepresentation: Data {
        self.backing.seedRepresentation
    }

    var integrityCheckedRepresentation: Data {
        fatalError()
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
        signature: S,
        for data: D
    ) -> Bool {
        self.backing.isValidSignature(signature, for: data)
    }

    func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(
        signature: S,
        for data: D,
        context: C
    ) -> Bool {
        self.backing.isValidSignature(signature, for: data, context: context)
    }

    var rawRepresentation: Data {
        self.backing.rawRepresentation
    }

    func prehash_boring<D: DataProtocol>(for data: D) throws -> Data {
        try self.backing.prehash(for: data)
    }

    func prehash_boring<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data {
        try self.backing.prehash(for: data, context: context)
    }
}

#endif  // CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
