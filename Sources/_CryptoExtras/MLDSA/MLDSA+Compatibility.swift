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
import Foundation

@available(iOS 19.0, macOS 16.0, watchOS 12.0, tvOS 19.0, visionOS 3.0, *)
extension MLDSA65.PublicKey {
    /// Verifies a MLDSA65 signature.
    /// - Parameters:
    ///   - signature: The MLDSA65 signature to verify.
    ///   - data: The signed data.
    /// - Returns: `true` if the signature is valid, `false` otherwise.
    @inlinable
    public func isValidSignature<S: DataProtocol, D: DataProtocol>(_ signature: S, for data: D) -> Bool {
        self.isValidSignature(signature: signature, for: data)
    }

    /// Verifies a MLDSA65 signature, in a specific context.
    /// - Parameters:
    ///   - signature: The MLDSA65 signature to verify.
    ///   - data: The signed data.
    ///   - context: Context for the signature.
    /// - Returns: `true` if the signature is valid in the specified context, `false` otherwise.
    @inlinable
    public func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(_ signature: S, for data: D, context: C) -> Bool {
        self.isValidSignature(signature: signature, for: data, context: context)
    }
}

@available(iOS 19.0, macOS 16.0, watchOS 12.0, tvOS 19.0, visionOS 3.0, *)
extension MLDSA87.PublicKey {
    /// Verifies a MLDSA87 signature.
    /// - Parameters:
    ///   - signature: The MLDSA87 signature to verify.
    ///   - data: The signed data.
    /// - Returns: `true` if the signature is valid, `false` otherwise.
    @inlinable
    public func isValidSignature<S: DataProtocol, D: DataProtocol>(_ signature: S, for data: D) -> Bool {
        self.isValidSignature(signature: signature, for: data)
    }

    /// Verifies a MLDSA87 signature, in a specific context.
    /// - Parameters:
    ///   - signature: The MLDSA87 signature to verify.
    ///   - data: The signed data.
    ///   - context: Context for the signature.
    /// - Returns: `true` if the signature is valid in the specified context, `false` otherwise.
    @inlinable
    public func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(_ signature: S, for data: D, context: C) -> Bool {
        self.isValidSignature(signature: signature, for: data, context: context)
    }
}

@available(iOS 19.0, macOS 16.0, watchOS 12.0, tvOS 19.0, visionOS 3.0, *)
extension MLDSA65.PrivateKey {
    /// Initializes a private key from the seed representation.
    ///
    /// - Parameter seedRepresentation: The seed representation of the private key. This parameter needs to be 32 bytes long.
    ///
    /// This initializer implements the `ML-DSA.KeyGen_internal` algorithm (Algorithm 16) of FIPS 204.
    ///
    /// If a public key is provided, a consistency check is performed between it and the derived public key.
    @inlinable
    public init<D: DataProtocol>(seedRepresentation: D) throws {
        try self.init(seedRepresentation: seedRepresentation, publicKey: nil)
    }
}

@available(iOS 19.0, macOS 16.0, watchOS 12.0, tvOS 19.0, visionOS 3.0, *)
extension MLDSA87.PrivateKey {
    /// Initializes a private key from the seed representation.
    ///
    /// - Parameter seedRepresentation: The seed representation of the private key. This parameter needs to be 32 bytes long.
    ///
    /// This initializer implements the `ML-DSA.KeyGen_internal` algorithm (Algorithm 16) of FIPS 204.
    ///
    /// If a public key is provided, a consistency check is performed between it and the derived public key.
    @inlinable
    public init<D: DataProtocol>(seedRepresentation: D) throws {
        try self.init(seedRepresentation: seedRepresentation, publicKey: nil)
    }
}
