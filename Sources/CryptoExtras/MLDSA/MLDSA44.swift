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

import Crypto
import CryptoBoringWrapper

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// The MLDSA44 Digital Signature Algorithm
@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
public enum MLDSA44: Sendable {}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
extension MLDSA44 {
    /// The public key for MLDSA44.
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    public struct PublicKey: Sendable {
        private let impl: BoringSSLMLDSA44.InternalPublicKey

        fileprivate init(_ impl: BoringSSLMLDSA44.InternalPublicKey) {
            self.impl = impl
        }

        /// Parses a public key from a serialized representation.
        ///
        /// - Parameter rawRepresentation: The public key, in the FIPS 204 standard serialization format.
        /// - Returns: The deserialized public key.
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            self.impl = try BoringSSLMLDSA44.InternalPublicKey(rawRepresentation: rawRepresentation)
        }
        
        /// A serialized representation of the public key.
        ///
        /// This property provides a representation of the public key in the FIPS 204 standard serialization format.
        public var rawRepresentation: Data {
            get {
                return self.impl.rawRepresentation
            }
        }

        /// Verifies a MLDSA44 signature.
        /// - Parameters:
        ///   - signature: The MLDSA44 signature to verify.
        ///   - data: The signed data.
        /// - Returns: `true` if the signature is valid, `false` otherwise.
        public func isValidSignature<S: DataProtocol, D: DataProtocol>(_ signature: S, for data: D) -> Bool {
            return self.impl.isValidSignature(signature, for: data)
        }

        /// Verifies a MLDSA44 signature, in a specific context.
        /// - Parameters:
        ///   - signature: The MLDSA44 signature to verify.
        ///   - data: The signed data.
        ///   - context: Context for the signature.
        /// - Returns: `true` if the signature is valid in the specified context, `false` otherwise.
        public func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(_ signature: S, for data: D, context: C) -> Bool {
            return self.impl.isValidSignature(signature, for: data, context: context)
        }
    }

    /// The private key for MLDSA44.
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    public struct PrivateKey: Sendable {
        private let impl: BoringSSLMLDSA44.InternalPrivateKey
        private let publicKeyHash: SHA3_256Digest
        
        /// Initializes a new random private key.
        public init() throws {
            self.impl = try BoringSSLMLDSA44.InternalPrivateKey()
            self.publicKeyHash = SHA3_256.hash(data: self.impl.publicKey.rawRepresentation)
        }

        /// Initializes a private key from the seed representation.
        ///
        /// - Parameter seedRepresentation: The seed representation of the private key. This parameter needs to be 32 bytes long.
        /// - Parameter publicKey: The public key associated with the secret key.
        ///
        /// This initializer implements the `ML-DSA.KeyGen_internal` algorithm (Algorithm 16) of FIPS 204.
        ///
        /// If a public key is provided, a consistency check is performed between it and the derived public key.
        public init<D: DataProtocol>(seedRepresentation: D, publicKey: MLDSA44.PublicKey?) throws {
            self.impl = try BoringSSLMLDSA44.InternalPrivateKey(seedRepresentation: seedRepresentation)
            if let publicKey {
                guard self.impl.publicKey.rawRepresentation == publicKey.rawRepresentation else {
                    throw CryptoError.authenticationFailure
                }
            }
            self.publicKeyHash = SHA3_256.hash(data: self.impl.publicKey.rawRepresentation)
        }
        
        /// The seed representation of the private key.
        ///
        /// The seed representation is 32 bytes long, and is the parameter
        /// for the `ML-DSA.KeyGen_internal` algorithm (Algorithm 16) of FIPS 204.
        public var seedRepresentation: Data {
            self.impl.seedRepresentation
        }

        /// Generates a MLDSA65 signature.
        /// - Parameters:
        ///   - data: The data to sign.
        /// - Returns: The MLDSA65 signature.
        /// This method throws if CryptoKit encounters an error producing the signature.
        public func signature<D: DataProtocol>(for data: D) throws -> Data {
            try impl.signature(for: data)
        }

        /// Generates a MLDSA65 signature, with context.
        /// - Parameters:
        ///   - data: The data to sign.
        ///   - context: Context for the signature.
        /// - Returns: The MLDSA65 signature.
        /// This method throws if CryptoKit encounters an error producing the signature.
        public func signature<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data {
            try impl.signature(for: data, context: context)
        }

        /// The associated public key.
        public var publicKey: PublicKey {
            PublicKey(self.impl.publicKey)
        }

        /// Initializes a private key from an integrity-checked data representation.
        ///
        /// - Parameter integrityCheckedRepresentation: The integrity-checked data representation of the private key.
        ///   The parameter needs to be 64 bytes long, and contain the seed and a hash of the public key.
        public init<D: DataProtocol>(integrityCheckedRepresentation: D) throws {
            let seedSize = BoringSSLMLDSA.seedByteCount
            guard integrityCheckedRepresentation.count == seedSize + 32 else {
                throw CryptoError.incorrectParameterSize
            }

            let seed = Data(integrityCheckedRepresentation).subdata(in: 0..<seedSize)
            let publicKeyHashData = Data(integrityCheckedRepresentation).subdata(in: seedSize..<integrityCheckedRepresentation.count)

            self.impl = try BoringSSLMLDSA44.InternalPrivateKey(seedRepresentation: seed)
            let generatedHash = SHA3_256.hash(data: self.impl.publicKey.rawRepresentation)
            guard generatedHash == publicKeyHashData else {
                throw CryptoError.authenticationFailure
            }
            self.publicKeyHash = generatedHash
        }

        /// The integrity-checked data representation of the private key.
        ///
        /// This representation is 64 bytes long, and contains the seed and a hash of the public key.
        public var integrityCheckedRepresentation: Data {
            var representation = self.seedRepresentation
            representation.reserveCapacity(SHA3_256Digest.byteCount)
            self.publicKeyHash.withUnsafeBytes {
                representation.append(contentsOf: $0)
            }
            return representation
        }
    }
}
