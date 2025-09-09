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
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias MLDSAPublicKeyImpl = CorecryptoMLDSAPublicKeyImpl
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias MLDSAPrivateKeyImpl = CorecryptoMLDSAPrivateKeyImpl
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
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public struct PublicKey: Sendable {
        var impl: MLDSAPublicKeyImpl<MLDSA65>

        internal init(_ impl: MLDSAPublicKeyImpl<MLDSA65>) {
            self.impl = impl
        }
        
        /// Parses a public key from a serialized representation.
        ///
        /// - Parameter rawRepresentation: The public key, in the FIPS 204 standard serialization format.
        /// - Returns: The deserialized public key.
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            self.impl = try MLDSAPublicKeyImpl(rawRepresentation: rawRepresentation)
        }
        
        /// A serialized representation of the public key.
        ///
        /// This property provides a representation of the public key in the FIPS 204 standard serialization format.
        public var rawRepresentation: Data {
            get {
                return self.impl.rawRepresentation
            }
        }

        /// Verifies a MLDSA65 signature.
        /// - Parameters:
        ///   - signature: The MLDSA65 signature to verify.
        ///   - data: The signed data.
        /// - Returns: `true` if the signature is valid, `false` otherwise.
        public func isValidSignature<S: DataProtocol, D: DataProtocol>(_ signature: S, for data: D) -> Bool {
            return self.impl.isValidSignature(signature, for: data)
        }

        /// Verifies a MLDSA65 signature, in a specific context.
        /// - Parameters:
        ///   - signature: The MLDSA65 signature to verify.
        ///   - data: The signed data.
        ///   - context: Context for the signature.
        /// - Returns: `true` if the signature is valid in the specified context, `false` otherwise.
        public func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(_ signature: S, for data: D, context: C) -> Bool {
            return self.impl.isValidSignature(signature, for: data, context: context)
        }
    }

    /// The private key for MLDSA65.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public struct PrivateKey: Signer, Sendable {
        internal let impl: MLDSAPrivateKeyImpl<MLDSA65>
        
        internal init(_ impl: MLDSAPrivateKeyImpl<MLDSA65>) {
            self.impl = impl
        }
        
        /// Initializes a new random private key.
        public init() throws {
            let impl = try MLDSAPrivateKeyImpl<MLDSA65>()
            self = PrivateKey(impl)
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
            var publicKeyRawRepresentation: Data? = nil
            if publicKey != nil {
                publicKeyRawRepresentation = publicKey!.rawRepresentation
            }
            self.impl = try MLDSAPrivateKeyImpl<MLDSA65>(seedRepresentation: seedRepresentation, publicKeyRawRepresentation: publicKeyRawRepresentation)
        }
        
        /// The seed representation of the private key.
        ///
        /// The seed representation is 32 bytes long, and is the parameter
        /// for the `ML-DSA.KeyGen_internal` algorithm (Algorithm 16) of FIPS 204.
        public var seedRepresentation: Data {
            get {
                return self.impl.seedRepresentation
            }
        }

        /// Generates a MLDSA65 signature.
        /// - Parameters:
        ///   - data: The data to sign.
        /// - Returns: The MLDSA65 signature.
        /// This method throws if CryptoKit encounters an error producing the signature.
        public func signature<D: DataProtocol>(for data: D) throws -> Data {
            return try impl.signature(for: data)
        }

        /// Generates a MLDSA65 signature, with context.
        /// - Parameters:
        ///   - data: The data to sign.
        ///   - context: Context for the signature.
        /// - Returns: The MLDSA65 signature.
        /// This method throws if CryptoKit encounters an error producing the signature.
        public func signature<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data {
            return try impl.signature(for: data, context: context)
        }
        
        /// The associated public key.
        public var publicKey: PublicKey {
            get {
                PublicKey(impl.publicKey)
            }
        }

        /// Initializes a private key from an integrity-checked data representation.
        ///
        /// - Parameter integrityCheckedRepresentation: The integrity-checked data representation of the private key.
        ///   The parameter needs to be 64 bytes long, and contain the seed and a hash of the public key.
        public init<D: DataProtocol>(integrityCheckedRepresentation: D) throws {
            let seedSize = MLDSAPrivateKeyImpl<MLDSA65>.seedSize
            guard integrityCheckedRepresentation.count == seedSize + 32 else {
                throw CryptoKitError.incorrectParameterSize
            }

            let seed = Data(integrityCheckedRepresentation).subdata(in: 0..<seedSize)
            let publicKeyHashData = Data(integrityCheckedRepresentation).subdata(in: seedSize..<integrityCheckedRepresentation.count)
            let publicKeyHash = SHA3_256Digest(bytes: [UInt8](publicKeyHashData))

            self.impl = try MLDSAPrivateKeyImpl<MLDSA65>(seedRepresentation: seed, publicKeyHash: publicKeyHash)
        }

        /// The integrity-checked data representation of the private key.
        ///
        /// This representation is 64 bytes long, and contains the seed and a hash of the public key.
        public var integrityCheckedRepresentation: Data {
            get {
                return self.impl.integrityCheckedRepresentation
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
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public struct PublicKey: Sendable {
        var impl: MLDSAPublicKeyImpl<MLDSA87>

        internal init(_ impl: MLDSAPublicKeyImpl<MLDSA87>) {
            self.impl = impl
        }
        
        /// Parses a public key from a serialized representation.
        ///
        /// - Parameter rawRepresentation: The public key, in the FIPS 204 standard serialization format.
        /// - Returns: The deserialized public key.
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            self.impl = try MLDSAPublicKeyImpl(rawRepresentation: rawRepresentation)
        }
        
        /// A serialized representation of the public key.
        ///
        /// This property provides a representation of the public key in the FIPS 204 standard serialization format.
        public var rawRepresentation: Data {
            get {
                return self.impl.rawRepresentation
            }
        }

        /// Verifies a MLDSA87 signature.
        /// - Parameters:
        ///   - signature: The MLDSA87 signature to verify.
        ///   - data: The signed data.
        /// - Returns: `true` if the signature is valid, `false` otherwise.
        public func isValidSignature<S: DataProtocol, D: DataProtocol>(_ signature: S, for data: D) -> Bool {
            return self.impl.isValidSignature(signature, for: data)
        }

        /// Verifies a MLDSA87 signature, in a specific context.
        /// - Parameters:
        ///   - signature: The MLDSA87 signature to verify.
        ///   - data: The signed data.
        ///   - context: Context for the signature.
        /// - Returns: `true` if the signature is valid in the specified context, `false` otherwise.
        public func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(_ signature: S, for data: D, context: C) -> Bool {
            return self.impl.isValidSignature(signature, for: data, context: context)
        }
    }

    /// The private key for MLDSA87.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public struct PrivateKey: Signer, Sendable {
        internal let impl: MLDSAPrivateKeyImpl<MLDSA87>
        
        internal init(_ impl: MLDSAPrivateKeyImpl<MLDSA87>) {
            self.impl = impl
        }
        
        /// Initializes a new random private key.
        public init() throws {
            let impl = try MLDSAPrivateKeyImpl<MLDSA87>()
            self = PrivateKey(impl)
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
            var publicKeyRawRepresentation: Data? = nil
            if publicKey != nil {
                publicKeyRawRepresentation = publicKey!.rawRepresentation
            }
            self.impl = try MLDSAPrivateKeyImpl<MLDSA87>(seedRepresentation: seedRepresentation, publicKeyRawRepresentation: publicKeyRawRepresentation)
        }
        
        /// The seed representation of the private key.
        ///
        /// The seed representation is 32 bytes long, and is the parameter
        /// for the `ML-DSA.KeyGen_internal` algorithm (Algorithm 16) of FIPS 204.
        public var seedRepresentation: Data {
            get {
                return self.impl.seedRepresentation
            }
        }

        /// Generates a MLDSA87 signature.
        /// - Parameters:
        ///   - data: The data to sign.
        /// - Returns: The MLDSA87 signature.
        /// This method throws if CryptoKit encounters an error producing the signature.
        public func signature<D: DataProtocol>(for data: D) throws -> Data {
            return try impl.signature(for: data)
        }

        /// Generates a MLDSA87 signature, with context.
        /// - Parameters:
        ///   - data: The data to sign.
        ///   - context: Context for the signature.
        /// - Returns: The MLDSA87 signature.
        /// This method throws if CryptoKit encounters an error producing the signature.
        public func signature<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data {
            return try impl.signature(for: data, context: context)
        }
        
        /// The associated public key.
        public var publicKey: PublicKey {
            get {
                PublicKey(impl.publicKey)
            }
        }

        /// Initializes a private key from an integrity-checked data representation.
        ///
        /// - Parameter integrityCheckedRepresentation: The integrity-checked data representation of the private key.
        ///   The parameter needs to be 64 bytes long, and contain the seed and a hash of the public key.
        public init<D: DataProtocol>(integrityCheckedRepresentation: D) throws {
            let seedSize = MLDSAPrivateKeyImpl<MLDSA87>.seedSize
            guard integrityCheckedRepresentation.count == seedSize + 32 else {
                throw CryptoKitError.incorrectParameterSize
            }

            let seed = Data(integrityCheckedRepresentation).subdata(in: 0..<seedSize)
            let publicKeyHashData = Data(integrityCheckedRepresentation).subdata(in: seedSize..<integrityCheckedRepresentation.count)
            let publicKeyHash = SHA3_256Digest(bytes: [UInt8](publicKeyHashData))

            self.impl = try MLDSAPrivateKeyImpl<MLDSA87>(seedRepresentation: seed, publicKeyHash: publicKeyHash)
        }

        /// The integrity-checked data representation of the private key.
        ///
        /// This representation is 64 bytes long, and contains the seed and a hash of the public key.
        public var integrityCheckedRepresentation: Data {
            get {
                return self.impl.integrityCheckedRepresentation
            }
        }
    }
}


#endif // Linux or !SwiftPM
