//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
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
#if canImport(FoundationEssentials)
public import FoundationEssentials
#else
public import Foundation
#endif

#if (!CRYPTO_IN_SWIFTPM_FORCE_BUILD_API) || CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
typealias MLKEMPublicKeyImpl = CoreCryptoMLKEMPublicKeyImpl
typealias MLKEMPrivateKeyImpl = CoreCryptoMLKEMPrivateKeyImpl
#else
typealias MLKEMPublicKeyImpl = OpenSSLMLKEMPublicKeyImpl
typealias MLKEMPrivateKeyImpl = OpenSSLMLKEMPrivateKeyImpl
#endif


/// The Module-Lattice key encapsulation mechanism (KEM).
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
public enum MLKEM768: Sendable {}

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
extension MLKEM768 {
    /// A public key you use to encapsulate shared secrets with the Module-Lattice key encapsulation mechanism.
    public struct PublicKey: KEMPublicKey, Sendable {
        var impl: MLKEMPublicKeyImpl<MLKEM768>

        /// Initializes a public key from a raw representation.
        /// - Parameter rawRepresentation: Data that represents the public key.
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            self.impl = try MLKEMPublicKeyImpl(rawRepresentation: rawRepresentation)
        }

        /// A serialized representation of the public key.
        public var rawRepresentation: Data {
            get {
                return self.impl.rawRepresentation
            }
        }

        /// Generates and encapsulates a shared secret.
        ///
        /// - Returns: an encapsulated shared secret, that you decapsulate by calling ``MLKEM768/PrivateKey/decapsulate(_:)`` on the corresponding private key.
        public func encapsulate() throws -> KEM.EncapsulationResult {
            return try self.impl.encapsulate()
        }

        func encapsulateWithSeed(encapSeed: Data) throws -> KEM.EncapsulationResult {
            return try self.impl.encapsulateWithSeed(encapSeed)
        }
    }

    /// A private key you use to decapsulate shared secrets with the Module-Lattice key encapsulation mechanism.
    public struct PrivateKey: KEMPrivateKey {
        internal let impl: MLKEMPrivateKeyImpl<MLKEM768>

        internal init(_ impl: MLKEMPrivateKeyImpl<MLKEM768>) {
            self.impl = impl
        }

        /// Generates a new, random private key.
        public static func generate() throws -> MLKEM768.PrivateKey {
            let impl = try MLKEMPrivateKeyImpl<MLKEM768>.generatePrivateKey()
            return PrivateKey(impl)
        }

        static func generateWithSeed(_ seed: Data) throws -> MLKEM768.PrivateKey {
            let impl = try MLKEMPrivateKeyImpl<MLKEM768>.generateWithSeed(seed)
            return PrivateKey(impl)
        }

        /// Initializes a random private key.
        public init() throws {
            self = try PrivateKey.generate()
        }

        /// Initializes a private key from a seed representation and optional public key.
        ///
        /// - Parameters:
        ///   - seedRepresentation: The seed representation `d||z`, as specified in the `ML-KEM.KeyGen_internal(d,z)` algorithm (Algorithm 16) of FIPS 203.
        ///   - publicKey: An optional public key. Pass this to check that the initialized private key is consistent with the public key. The initializer throws if the public key doesn't match the expected value.
        public init<D: DataProtocol>(seedRepresentation: D, publicKey: MLKEM768.PublicKey?) throws {
            var publicKeyRawRepresentation: Data? = nil
            if publicKey != nil {
                publicKeyRawRepresentation = publicKey!.rawRepresentation
            }
            self.impl = try MLKEMPrivateKeyImpl<MLKEM768>(seedRepresentation: seedRepresentation, publicKeyRawRepresentation: publicKeyRawRepresentation)
        }

        /// The private key's seed representation.
        ///
        /// The seed is `d||z`, as specified in the algorithm `ML-KEM.KeyGen_internal(d,z)` (Algorithm 16) of FIPS 203.
        public var seedRepresentation: Data {
            get {
                return self.impl.seedRepresentation
            }
        }

        /// Decapsulate a shared secret.
        ///
        /// - Parameters:
        ///   - encapsulated: An encapsulated shared secret, that you get by calling ``MLKEM768/PublicKey/encapsulate()`` on the corresponding public key.
        /// - Returns: The shared secret.
        public func decapsulate<D: DataProtocol>(_ encapsulated: D) throws -> SymmetricKey {
            return try impl.decapsulate(encapsulated: encapsulated)
        }

        /// The corresponding public key.
        public var publicKey: MLKEM768.PublicKey {
            get {
                self.impl.publicKey
            }
        }

        /// Initializes a private key from an integrity-checked representation.
        ///
        /// - Parameter integrityCheckedRepresentation: A representation of the private key that includes the seed value, and a hash of the corresponding public key.
        public init<D: DataProtocol>(integrityCheckedRepresentation: D) throws {
            guard integrityCheckedRepresentation.count == MLKEMPrivateKeyImpl<MLKEM768>.seedSize + 32 else {
                throw KEM.Errors.invalidSeed
            }
            let seed = Data(integrityCheckedRepresentation).subdata(in: 0..<MLKEMPrivateKeyImpl<MLKEM768>.seedSize)
            let publicKeyHashData = Data(integrityCheckedRepresentation).subdata(in: MLKEMPrivateKeyImpl<MLKEM768>.seedSize..<integrityCheckedRepresentation.count)
            let publicKeyHash = SHA3_256Digest(copying: publicKeyHashData.bytes)

            self.impl = try MLKEMPrivateKeyImpl<MLKEM768>(seedRepresentation: seed, publicKeyHash: publicKeyHash)
        }

        /// An integrity-checked representation of the private key.
        ///
        /// This representation includes the seed value, and a hash of the corresponding public key.
        public var integrityCheckedRepresentation: Data {
            get {
                return self.impl.integrityCheckedRepresentation
            }
        }
    }

    @available(iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0, macCatalyst 27.0, visionOS 27.0, *)
    /// A one-time-use private key to decapsulate a shared secret with the Module-Lattice key encapsulation mechanism.
    ///
    /// The associated decapsulation function can be multiple times faster than the one implemented for PrivateKey,
    /// but this private key can only be used to decapsulate a shared secret once.
    public struct OneTimePrivateKey: KEMOneTimePrivateKey, ~Copyable {
        internal let impl: MLKEMPrivateKeyImpl<MLKEM768>

        internal init(_ impl: MLKEMPrivateKeyImpl<MLKEM768>) {
            self.impl = impl
        }

        /// Generates a new, random one-time-use private key.
        public static func generate() throws -> MLKEM768.OneTimePrivateKey {
            let impl = try MLKEMPrivateKeyImpl<MLKEM768>.generatePrivateKey()
            return OneTimePrivateKey(impl)
        }

        /// Initializes a random one-time-use private key.
        public init() throws {
            self = try OneTimePrivateKey.generate()
        }

        /// Decapsulate a shared secret.
        ///
        /// - Parameters:
        ///   - encapsulated: An encapsulated shared secret, that you get by calling ``MLKEM768/PublicKey/encapsulate()`` on the corresponding public key.
        /// - Returns: The shared secret.
        public consuming func decapsulate<D: DataProtocol>(_ encapsulated: D) throws -> SymmetricKey {
            return try impl.decapsulate(encapsulated: encapsulated)
        }

        /// The corresponding public key.
        public var publicKey: MLKEM768.PublicKey {
            get {
                self.impl.publicKey
            }
        }
    }
}


/// The Module-Lattice key encapsulation mechanism (KEM).
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
public enum MLKEM1024: Sendable {}

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
extension MLKEM1024 {
    /// A public key you use to encapsulate shared secrets with the Module-Lattice key encapsulation mechanism.
    public struct PublicKey: KEMPublicKey, Sendable {
        var impl: MLKEMPublicKeyImpl<MLKEM1024>

        /// Initializes a public key from a raw representation.
        /// - Parameter rawRepresentation: Data that represents the public key.
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            self.impl = try MLKEMPublicKeyImpl(rawRepresentation: rawRepresentation)
        }

        /// A serialized representation of the public key.
        public var rawRepresentation: Data {
            get {
                return self.impl.rawRepresentation
            }
        }

        /// Generates and encapsulates a shared secret.
        ///
        /// - Returns: an encapsulated shared secret, that you decapsulate by calling ``MLKEM1024/PrivateKey/decapsulate(_:)`` on the corresponding private key.
        public func encapsulate() throws -> KEM.EncapsulationResult {
            return try self.impl.encapsulate()
        }

        func encapsulateWithSeed(encapSeed: Data) throws -> KEM.EncapsulationResult {
            return try self.impl.encapsulateWithSeed(encapSeed)
        }
    }

    /// A private key you use to decapsulate shared secrets with the Module-Lattice key encapsulation mechanism.
    public struct PrivateKey: KEMPrivateKey {
        internal let impl: MLKEMPrivateKeyImpl<MLKEM1024>

        internal init(_ impl: MLKEMPrivateKeyImpl<MLKEM1024>) {
            self.impl = impl
        }

        /// Generates a new, random private key.
        public static func generate() throws -> MLKEM1024.PrivateKey {
            let impl = try MLKEMPrivateKeyImpl<MLKEM1024>.generatePrivateKey()
            return PrivateKey(impl)
        }

        static func generateWithSeed(_ seed: Data) throws -> MLKEM1024.PrivateKey {
            let impl = try MLKEMPrivateKeyImpl<MLKEM1024>.generateWithSeed(seed)
            return PrivateKey(impl)
        }

        /// Initializes a random private key.
        public init() throws {
            self = try PrivateKey.generate()
        }

        /// Initializes a private key from a seed representation and optional public key.
        ///
        /// - Parameters:
        ///   - seedRepresentation: The seed representation `d||z`, as specified in the `ML-KEM.KeyGen_internal(d,z)` algorithm (Algorithm 16) of FIPS 203.
        ///   - publicKey: An optional public key. Pass this to check that the initialized private key is consistent with the public key. The initializer throws if the public key doesn't match the expected value.
        public init<D: DataProtocol>(seedRepresentation: D, publicKey: MLKEM1024.PublicKey?) throws {
            var publicKeyRawRepresentation: Data? = nil
            if publicKey != nil {
                publicKeyRawRepresentation = publicKey!.rawRepresentation
            }
            self.impl = try MLKEMPrivateKeyImpl<MLKEM1024>(seedRepresentation: seedRepresentation, publicKeyRawRepresentation: publicKeyRawRepresentation)
        }

        /// The private key's seed representation.
        ///
        /// The seed is `d||z`, as specified in the algorithm `ML-KEM.KeyGen_internal(d,z)` (Algorithm 16) of FIPS 203.
        public var seedRepresentation: Data {
            get {
                return self.impl.seedRepresentation
            }
        }

        /// Decapsulate a shared secret.
        ///
        /// - Parameters:
        ///   - encapsulated: An encapsulated shared secret, that you get by calling ``MLKEM1024/PublicKey/encapsulate()`` on the corresponding public key.
        /// - Returns: The shared secret.
        public func decapsulate<D: DataProtocol>(_ encapsulated: D) throws -> SymmetricKey {
            return try impl.decapsulate(encapsulated: encapsulated)
        }

        /// The corresponding public key.
        public var publicKey: MLKEM1024.PublicKey {
            get {
                self.impl.publicKey
            }
        }

        /// Initializes a private key from an integrity-checked representation.
        ///
        /// - Parameter integrityCheckedRepresentation: A representation of the private key that includes the seed value, and a hash of the corresponding public key.
        public init<D: DataProtocol>(integrityCheckedRepresentation: D) throws {
            guard integrityCheckedRepresentation.count == MLKEMPrivateKeyImpl<MLKEM1024>.seedSize + 32 else {
                throw KEM.Errors.invalidSeed
            }
            let seed = Data(integrityCheckedRepresentation).subdata(in: 0..<MLKEMPrivateKeyImpl<MLKEM1024>.seedSize)
            let publicKeyHashData = Data(integrityCheckedRepresentation).subdata(in: MLKEMPrivateKeyImpl<MLKEM1024>.seedSize..<integrityCheckedRepresentation.count)
            let publicKeyHash = SHA3_256Digest(copying: publicKeyHashData.bytes)

            self.impl = try MLKEMPrivateKeyImpl<MLKEM1024>(seedRepresentation: seed, publicKeyHash: publicKeyHash)
        }

        /// An integrity-checked representation of the private key.
        ///
        /// This representation includes the seed value, and a hash of the corresponding public key.
        public var integrityCheckedRepresentation: Data {
            get {
                return self.impl.integrityCheckedRepresentation
            }
        }
    }

    @available(iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0, macCatalyst 27.0, visionOS 27.0, *)
    /// A one-time-use private key to decapsulate a shared secret with the Module-Lattice key encapsulation mechanism.
    ///
    /// The associated decapsulation function can be multiple times faster than the one implemented for PrivateKey,
    /// but this private key can only be used to decapsulate a shared secret once.
    public struct OneTimePrivateKey: KEMOneTimePrivateKey, ~Copyable {
        internal let impl: MLKEMPrivateKeyImpl<MLKEM1024>

        internal init(_ impl: MLKEMPrivateKeyImpl<MLKEM1024>) {
            self.impl = impl
        }

        /// Generates a new, random one-time-use private key.
        public static func generate() throws -> MLKEM1024.OneTimePrivateKey {
            let impl = try MLKEMPrivateKeyImpl<MLKEM1024>.generatePrivateKey()
            return OneTimePrivateKey(impl)
        }

        /// Initializes a random one-time-use private key.
        public init() throws {
            self = try OneTimePrivateKey.generate()
        }

        /// Decapsulate a shared secret.
        ///
        /// - Parameters:
        ///   - encapsulated: An encapsulated shared secret, that you get by calling ``MLKEM1024/PublicKey/encapsulate()`` on the corresponding public key.
        /// - Returns: The shared secret.
        public consuming func decapsulate<D: DataProtocol>(_ encapsulated: D) throws -> SymmetricKey {
            return try impl.decapsulate(encapsulated: encapsulated)
        }

        /// The corresponding public key.
        public var publicKey: MLKEM1024.PublicKey {
            get {
                self.impl.publicKey
            }
        }
    }
}


#endif // Linux or !SwiftPM
