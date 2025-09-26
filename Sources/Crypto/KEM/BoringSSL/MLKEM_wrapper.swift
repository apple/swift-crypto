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
protocol BoringSSLBackedMLKEMPrivateKey: Sendable {
    associatedtype InteriorPublicKey: BoringSSLBackedMLKEMPublicKey

    static func generatePrivateKey() throws -> Self

    static func generateWithSeed(_ seed: Data) throws -> Self

    init<Bytes: DataProtocol>(seedRepresentation: Bytes, publicKeyRawRepresentation: Data?) throws

    init<Bytes: DataProtocol>(seedRepresentation: Bytes, publicKeyHash: SHA3_256Digest?) throws

    var seedRepresentation: Data { get }

    func decapsulate<Bytes: DataProtocol>(_ encapsulated: Bytes) throws -> SymmetricKey

    var interiorPublicKey: InteriorPublicKey { get }

    var integrityCheckedRepresentation: Data { get }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLBackedMLKEMPrivateKey {
    func decapsulate<Bytes: DataProtocol>(encapsulated: Bytes) throws -> SymmetricKey {
        try self.decapsulate(encapsulated)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
protocol BoringSSLBackedMLKEMPublicKey: Sendable {
    init<Bytes: DataProtocol>(rawRepresentation: Bytes) throws

    var rawRepresentation: Data { get }

    func encapsulate() throws -> KEM.EncapsulationResult

    func encapsulateWithSeed(_ encapSeed: Data) throws -> KEM.EncapsulationResult
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
protocol BoringSSLBackedMLKEMOuterPublicKey: Sendable {
    init(rawRepresentation: Data) throws
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
protocol BoringSSLBackedMLKEMParameters {
    associatedtype BackingPrivateKey: BoringSSLBackedMLKEMPrivateKey
    where BackingPrivateKey.InteriorPublicKey == BackingPublicKey
    associatedtype BackingPublicKey: BoringSSLBackedMLKEMPublicKey
    associatedtype PublicKey: BoringSSLBackedMLKEMOuterPublicKey
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLKEM768: BoringSSLBackedMLKEMParameters {
    typealias BackingPrivateKey = MLKEM768.InternalPrivateKey
    typealias BackingPublicKey = MLKEM768.InternalPublicKey
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLKEM768.PublicKey: BoringSSLBackedMLKEMOuterPublicKey {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLKEM768.InternalPrivateKey: BoringSSLBackedMLKEMPrivateKey {
    static func generatePrivateKey() throws -> Self {
        .generate()
    }

    static func generateWithSeed(_ seed: Data) throws -> Self {
        let seed = Array(seed)
        var fullSeed: [UInt8] = []
        fullSeed.reserveCapacity(MLKEM.seedByteCount)

        for i in 0..<MLKEM.seedByteCount {
            fullSeed.append(seed[i % seed.count])
        }

        return try .init(seedRepresentation: fullSeed)
    }

    init<Bytes>(seedRepresentation: Bytes, publicKeyRawRepresentation: Data?) throws where Bytes: DataProtocol {
        let publicKeyHash = publicKeyRawRepresentation.map {
            SHA3_256.hash(data: $0)
        }
        self = try .init(seedRepresentation: seedRepresentation, publicKeyHash: publicKeyHash)
    }

    init<Bytes: DataProtocol>(seedRepresentation: Bytes, publicKeyHash: SHA3_256Digest?) throws {
        self = try .init(seedRepresentation: seedRepresentation)
        let generatedHash = SHA3_256.hash(data: self.publicKey.rawRepresentation)
        if let publicKeyHash, generatedHash != publicKeyHash {
            throw KEM.Errors.publicKeyMismatchDuringInitialization
        }
    }

    var integrityCheckedRepresentation: Data {
        var representation = self.seedRepresentation
        SHA3_256.hash(data: self.publicKey.rawRepresentation).withUnsafeBytes {
            representation.append(contentsOf: $0)
        }
        return representation
    }

    var interiorPublicKey: MLKEM768.InternalPublicKey {
        self.publicKey
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLKEM768.InternalPublicKey: BoringSSLBackedMLKEMPublicKey {
    func encapsulateWithSeed(_ encapSeed: Data) throws -> KEM.EncapsulationResult {
        fatalError()
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLKEM1024: BoringSSLBackedMLKEMParameters {
    typealias BackingPrivateKey = MLKEM1024.InternalPrivateKey
    typealias BackingPublicKey = MLKEM1024.InternalPublicKey
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLKEM1024.PublicKey: BoringSSLBackedMLKEMOuterPublicKey {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLKEM1024.InternalPrivateKey: BoringSSLBackedMLKEMPrivateKey {
    static func generatePrivateKey() throws -> Self {
        .generate()
    }

    static func generateWithSeed(_ seed: Data) throws -> Self {
        let seed = Array(seed)
        var fullSeed: [UInt8] = []
        fullSeed.reserveCapacity(MLKEM.seedByteCount)

        for i in 0..<MLKEM.seedByteCount {
            fullSeed.append(seed[i % seed.count])
        }

        return try .init(seedRepresentation: fullSeed)
    }

    init<Bytes>(seedRepresentation: Bytes, publicKeyRawRepresentation: Data?) throws where Bytes: DataProtocol {
        let publicKeyHash = publicKeyRawRepresentation.map {
            SHA3_256.hash(data: $0)
        }
        self = try .init(seedRepresentation: seedRepresentation, publicKeyHash: publicKeyHash)
    }

    init<Bytes: DataProtocol>(seedRepresentation: Bytes, publicKeyHash: SHA3_256Digest?) throws {
        self = try .init(seedRepresentation: seedRepresentation)
        let generatedHash = SHA3_256.hash(data: self.publicKey.rawRepresentation)
        if let publicKeyHash, generatedHash != publicKeyHash {
            throw KEM.Errors.publicKeyMismatchDuringInitialization
        }
    }

    var integrityCheckedRepresentation: Data {
        var representation = self.seedRepresentation
        SHA3_256.hash(data: self.publicKey.rawRepresentation).withUnsafeBytes {
            representation.append(contentsOf: $0)
        }
        return representation
    }

    var interiorPublicKey: MLKEM1024.InternalPublicKey {
        self.publicKey
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLKEM1024.InternalPublicKey: BoringSSLBackedMLKEMPublicKey {
    func encapsulateWithSeed(_ encapSeed: Data) throws -> KEM.EncapsulationResult {
        fatalError()
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct OpenSSLMLKEMPublicKeyImpl<Parameters: BoringSSLBackedMLKEMParameters>: BoringSSLBackedMLKEMPublicKey, Sendable {
    private var backing: Parameters.BackingPublicKey

    init(backing: Parameters.BackingPublicKey) {
        self.backing = backing
    }

    init<Bytes>(rawRepresentation: Bytes) throws where Bytes: DataProtocol {
        self.backing = try .init(rawRepresentation: rawRepresentation)
    }

    var rawRepresentation: Data {
        self.backing.rawRepresentation
    }

    func encapsulate() throws -> KEM.EncapsulationResult {
        try self.backing.encapsulate()
    }

    func encapsulateWithSeed(_ encapSeed: Data) throws -> KEM.EncapsulationResult {
        try self.backing.encapsulateWithSeed(encapSeed)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct OpenSSLMLKEMPrivateKeyImpl<Parameters: BoringSSLBackedMLKEMParameters>: BoringSSLBackedMLKEMPrivateKey, Sendable
{
    typealias InteriorPublicKey = OpenSSLMLKEMPublicKeyImpl<Parameters>

    private var backing: Parameters.BackingPrivateKey

    init(backing: Parameters.BackingPrivateKey) {
        self.backing = backing
    }

    static func generatePrivateKey() throws -> Self {
        try Self(backing: .generatePrivateKey())
    }

    static func generateWithSeed(_ seed: Data) throws -> Self {
        try Self(backing: .generateWithSeed(seed))
    }

    init<Bytes: DataProtocol>(
        seedRepresentation: Bytes,
        publicKeyRawRepresentation: Data?
    ) throws {
        self.backing = try .init(
            seedRepresentation: seedRepresentation,
            publicKeyRawRepresentation: publicKeyRawRepresentation
        )
    }

    init<Bytes: DataProtocol>(
        seedRepresentation: Bytes,
        publicKeyHash: SHA3_256Digest?
    ) throws {
        self.backing = try .init(
            seedRepresentation: seedRepresentation,
            publicKeyHash: publicKeyHash
        )
    }

    var seedRepresentation: Data {
        self.backing.seedRepresentation
    }

    func decapsulate<Bytes>(_ encapsulated: Bytes) throws -> SymmetricKey where Bytes: DataProtocol {
        try self.backing.decapsulate(encapsulated)
    }

    var interiorPublicKey: InteriorPublicKey {
        .init(backing: self.backing.interiorPublicKey)
    }

    var publicKey: Parameters.PublicKey {
        get {
            try! .init(rawRepresentation: self.interiorPublicKey.rawRepresentation)
        }
    }

    var integrityCheckedRepresentation: Data {
        self.backing.integrityCheckedRepresentation
    }

    static var seedSize: Int {
        MLKEM.seedByteCount
    }
}

#endif  // CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
