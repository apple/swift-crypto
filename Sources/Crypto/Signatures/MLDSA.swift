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
typealias MLDSAPublicKeyImpl = CoreCryptoMLDSAPublicKeyImpl
typealias MLDSAPrivateKeyImpl = CoreCryptoMLDSAPrivateKeyImpl
#else
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias MLDSAPublicKeyImpl = OpenSSLMLDSAPublicKeyImpl
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias MLDSAPrivateKeyImpl = OpenSSLMLDSAPrivateKeyImpl
#endif

/// The MLDSA65 Digital Signature Algorithm
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public enum MLDSA65: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLDSA65 {
    /// The public key for MLDSA65.
    public struct PublicKey: Sendable {
        var impl: MLDSAPublicKeyImpl<MLDSA65>

        /// Verifies a MLDSA65 signature.
        /// - Parameters:
        ///   - signature: The MLDSA65 signature to verify.
        ///   - data: The signed data.
        /// - Returns: `true` if the signature is valid, `false` otherwise.
        public func isValidSignature<S: DataProtocol, D: DataProtocol>(signature: S, for data: D) -> Bool {
            self.impl.isValidSignature(signature: signature, for: data)
        }

        /// Verifies a MLDSA65 signature, in a specific context.
        /// - Parameters:
        ///   - signature: The MLDSA65 signature to verify.
        ///   - data: The signed data.
        ///   - context: Context for the signature.
        /// - Returns: `true` if the signature is valid in the specified context, `false` otherwise.
        public func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(
            signature: S,
            for data: D,
            context: C
        ) -> Bool {
            self.impl.isValidSignature(signature: signature, for: data, context: context)
        }

        /// Parses a public key from a serialized representation.
        ///
        /// - Parameter rawRepresentation: The public key, in the FIPS 204 standard serialization format.
        /// - Returns: The deserialized public key.
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            self.impl = try .init(rawRepresentation: rawRepresentation)
        }

        /// A serialized representation of the public key.
        ///
        /// This property provides a representation of the public key in the FIPS 204 standard serialization format.
        public var rawRepresentation: Data {
            get {
                self.impl.rawRepresentation
            }
        }

        fileprivate init(impl: MLDSAPublicKeyImpl<MLDSA65>) {
            self.impl = impl
        }

        /// Generate a prehashed message representative (a.k.a. "external mu") for the given message.
        ///
        /// - Parameter data: The message to prehash.
        ///
        /// - Returns: The prehashed message representative (a.k.a. "external mu").
        package func prehash_boring<D: DataProtocol>(for data: D) throws -> Data {
            try self.boringSSLKey.prehash_boring(for: data)
        }

        /// Generate a prehashed message representative (a.k.a. "external mu") for the given message.
        ///
        /// - Parameters:
        ///   - data: The message to prehash.
        ///   - context: The context of the message.
        ///
        /// - Returns: The prehashed message representative (a.k.a. "external mu").
        package func prehash_boring<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data {
            try self.boringSSLKey.prehash_boring(for: data, context: context)
        }

        private var boringSSLKey: OpenSSLMLDSAPublicKeyImpl<MLDSA65> {
            get throws {
                #if (!CRYPTO_IN_SWIFTPM_FORCE_BUILD_API) || CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
                try OpenSSLMLDSAPublicKeyImpl<MLDSA65>(rawRepresentation: self.rawRepresentation)
                #else
                self.impl
                #endif
            }
        }
    }

    /// The private key for MLDSA65.
    public struct PrivateKey: Signer, Sendable {
        var impl: MLDSAPrivateKeyImpl<MLDSA65>

        /// Generates a MLDSA65 signature.
        /// - Parameters:
        ///   - data: The data to sign.
        /// - Returns: The MLDSA65 signature.
        /// This method throws if CryptoKit encounters an error producing the signature.
        public func signature<D: DataProtocol>(for data: D) throws -> Data {
            try self.impl.signature(for: data)
        }

        /// Generates a MLDSA65 signature, with context.
        /// - Parameters:
        ///   - data: The data to sign.
        ///   - context: Context for the signature.
        /// - Returns: The MLDSA65 signature.
        /// This method throws if CryptoKit encounters an error producing the signature.
        public func signature<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data {
            try self.impl.signature(for: data, context: context)
        }

        /// Generate a signature for the prehashed message representative (a.k.a. "external mu").
        ///
        /// > Note: The message representative should be obtained via calls to ``MLDSA87/PublicKey/prehash(for:context:)``.
        ///
        /// - Parameter mu: The prehashed message representative (a.k.a. "external mu").
        ///
        /// - Returns: The signature of the prehashed message representative.
        package func signature_boring(forPrehashedMessageRepresentative mu: some DataProtocol) throws -> Data {
            try self.boringSSLKey.signature_boring(forPrehashedMessageRepresentative: mu)
        }

        /// The associated public key.
        public var publicKey: PublicKey {
            get {
                PublicKey(impl: self.impl.publicKey)
            }
        }

        /// Initializes a new random private key.
        public init() throws {
            self.impl = try .init()
        }

        /// Initializes a private key from the seed representation.
        ///
        /// - Parameter seedRepresentation: The seed representation of the private key. This parameter needs to be 32 bytes long.
        /// - Parameter publicKey: The public key associated with the secret key.
        ///
        /// This initializer implements the `ML-DSA.KeyGen_internal` algorithm (Algorithm 16) of FIPS 204.
        ///
        /// If a public key is provided, a consistency check is performed between it and the derived public key.
        public init<D: DataProtocol>(seedRepresentation: D, publicKey: MLDSA65.PublicKey?) throws {
            self.impl = try .init(seedRepresentation: seedRepresentation, publicKey: publicKey?.impl)
        }

        /// The seed representation of the private key.
        ///
        /// The seed representation is 32 bytes long, and is the parameter
        /// for the `ML-DSA.KeyGen_internal` algorithm (Algorithm 16) of FIPS 204.
        public var seedRepresentation: Data {
            get {
                self.impl.seedRepresentation
            }
        }

        /// Initializes a private key from an integrity-checked data representation.
        ///
        /// - Parameter integrityCheckedRepresentation: The integrity-checked data representation of the private key.
        ///   The parameter needs to be 64 bytes long, and contain the seed and a hash of the public key.
        public init<D: DataProtocol>(integrityCheckedRepresentation: D) throws {
            self.impl = try .init(integrityCheckedRepresentation: integrityCheckedRepresentation)
        }

        /// The integrity-checked data representation of the private key.
        ///
        /// This representation is 64 bytes long, and contains the seed and a hash of the public key.
        public var integrityCheckedRepresentation: Data {
            get {
                self.impl.integrityCheckedRepresentation
            }
        }

        private init(impl: MLDSAPrivateKeyImpl<MLDSA65>) {
            self.impl = impl
        }

        private var boringSSLKey: OpenSSLMLDSAPrivateKeyImpl<MLDSA65> {
            get throws {
                #if (!CRYPTO_IN_SWIFTPM_FORCE_BUILD_API) || CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
                try OpenSSLMLDSAPrivateKeyImpl<MLDSA65>(
                    seedRepresentation: self.seedRepresentation,
                    publicKey: nil
                )
                #else
                self.impl
                #endif
            }
        }
    }
}

/// The MLDSA87 Digital Signature Algorithm
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public enum MLDSA87: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLDSA87 {
    /// The public key for MLDSA87.
    public struct PublicKey: Sendable {
        var impl: MLDSAPublicKeyImpl<MLDSA87>

        /// Verifies a MLDSA87 signature.
        /// - Parameters:
        ///   - signature: The MLDSA87 signature to verify.
        ///   - data: The signed data.
        /// - Returns: `true` if the signature is valid, `false` otherwise.
        public func isValidSignature<S: DataProtocol, D: DataProtocol>(signature: S, for data: D) -> Bool {
            self.impl.isValidSignature(signature: signature, for: data)
        }

        /// Verifies a MLDSA87 signature, in a specific context.
        /// - Parameters:
        ///   - signature: The MLDSA87 signature to verify.
        ///   - data: The signed data.
        ///   - context: Context for the signature.
        /// - Returns: `true` if the signature is valid in the specified context, `false` otherwise.
        public func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(
            signature: S,
            for data: D,
            context: C
        ) -> Bool {
            self.impl.isValidSignature(signature: signature, for: data, context: context)
        }

        /// Parses a public key from a serialized representation.
        ///
        /// - Parameter rawRepresentation: The public key, in the FIPS 204 standard serialization format.
        /// - Returns: The deserialized public key.
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            self.impl = try .init(rawRepresentation: rawRepresentation)
        }

        /// A serialized representation of the public key.
        ///
        /// This property provides a representation of the public key in the FIPS 204 standard serialization format.
        public var rawRepresentation: Data {
            get {
                self.impl.rawRepresentation
            }
        }

        fileprivate init(impl: MLDSAPublicKeyImpl<MLDSA87>) {
            self.impl = impl
        }

        /// Generate a prehashed message representative (a.k.a. "external mu") for the given message.
        ///
        /// - Parameter data: The message to prehash.
        ///
        /// - Returns: The prehashed message representative (a.k.a. "external mu").
        package func prehash_boring<D: DataProtocol>(for data: D) throws -> Data {
            try self.boringSSLKey.prehash_boring(for: data)
        }

        /// Generate a prehashed message representative (a.k.a. "external mu") for the given message.
        ///
        /// - Parameters:
        ///   - data: The message to prehash.
        ///   - context: The context of the message.
        ///
        /// - Returns: The prehashed message representative (a.k.a. "external mu").
        package func prehash_boring<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data {
            try self.boringSSLKey.prehash_boring(for: data, context: context)
        }

        private var boringSSLKey: OpenSSLMLDSAPublicKeyImpl<MLDSA87> {
            get throws {
                #if (!CRYPTO_IN_SWIFTPM_FORCE_BUILD_API) || CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
                try OpenSSLMLDSAPublicKeyImpl<MLDSA87>(rawRepresentation: self.rawRepresentation)
                #else
                self.impl
                #endif
            }
        }
    }

    /// The private key for MLDSA87.
    public struct PrivateKey: Signer, Sendable {
        var impl: MLDSAPrivateKeyImpl<MLDSA87>

        /// Generates a MLDSA87 signature.
        /// - Parameters:
        ///   - data: The data to sign.
        /// - Returns: The MLDSA87 signature.
        /// This method throws if CryptoKit encounters an error producing the signature.
        public func signature<D: DataProtocol>(for data: D) throws -> Data {
            try self.impl.signature(for: data)
        }

        /// Generates a MLDSA87 signature, with context.
        /// - Parameters:
        ///   - data: The data to sign.
        ///   - context: Context for the signature.
        /// - Returns: The MLDSA87 signature.
        /// This method throws if CryptoKit encounters an error producing the signature.
        public func signature<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data {
            try self.impl.signature(for: data, context: context)
        }

        /// Generate a signature for the prehashed message representative (a.k.a. "external mu").
        ///
        /// > Note: The message representative should be obtained via calls to ``MLDSA87/PublicKey/prehash(for:context:)``.
        ///
        /// - Parameter mu: The prehashed message representative (a.k.a. "external mu").
        ///
        /// - Returns: The signature of the prehashed message representative.
        package func signature_boring(forPrehashedMessageRepresentative mu: some DataProtocol) throws -> Data {
            try self.boringSSLKey.signature_boring(forPrehashedMessageRepresentative: mu)
        }

        /// The associated public key.
        public var publicKey: PublicKey {
            get {
                PublicKey(impl: self.impl.publicKey)
            }
        }

        /// Initializes a new random private key.
        public init() throws {
            self.impl = try .init()
        }

        /// Initializes a private key from the seed representation.
        ///
        /// - Parameter seedRepresentation: The seed representation of the private key. This parameter needs to be 32 bytes long.
        /// - Parameter publicKey: The public key associated with the secret key.
        ///
        /// This initializer implements the `ML-DSA.KeyGen_internal` algorithm (Algorithm 16) of FIPS 204.
        ///
        /// If a public key is provided, a consistency check is performed between it and the derived public key.
        public init<D: DataProtocol>(seedRepresentation: D, publicKey: MLDSA87.PublicKey?) throws {
            self.impl = try .init(seedRepresentation: seedRepresentation, publicKey: publicKey?.impl)
        }

        /// The seed representation of the private key.
        ///
        /// The seed representation is 32 bytes long, and is the parameter
        /// for the `ML-DSA.KeyGen_internal` algorithm (Algorithm 16) of FIPS 204.
        public var seedRepresentation: Data {
            get {
                self.impl.seedRepresentation
            }
        }

        /// Initializes a private key from an integrity-checked data representation.
        ///
        /// - Parameter integrityCheckedRepresentation: The integrity-checked data representation of the private key.
        ///   The parameter needs to be 64 bytes long, and contain the seed and a hash of the public key.
        public init<D: DataProtocol>(integrityCheckedRepresentation: D) throws {
            self.impl = try .init(integrityCheckedRepresentation: integrityCheckedRepresentation)
        }

        /// The integrity-checked data representation of the private key.
        ///
        /// This representation is 64 bytes long, and contains the seed and a hash of the public key.
        public var integrityCheckedRepresentation: Data {
            get {
                self.impl.integrityCheckedRepresentation
            }
        }

        private init(impl: MLDSAPrivateKeyImpl<MLDSA87>) {
            self.impl = impl
        }

        private var boringSSLKey: OpenSSLMLDSAPrivateKeyImpl<MLDSA87> {
            get throws {
                #if (!CRYPTO_IN_SWIFTPM_FORCE_BUILD_API) || CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
                try OpenSSLMLDSAPrivateKeyImpl<MLDSA87>(
                    seedRepresentation: self.seedRepresentation,
                    publicKey: nil
                )
                #else
                self.impl
                #endif
            }
        }
    }
}

#endif  // Linux or !SwiftPM
