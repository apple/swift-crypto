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
extension MLKEM768.PrivateKey {
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
extension MLKEM1024.PrivateKey {
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
