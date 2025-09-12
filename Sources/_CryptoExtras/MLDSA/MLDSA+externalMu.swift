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

// MARK: - Generated file, do NOT edit
// any edits of this file WILL be overwritten and thus discarded
// see section `gyb` in `README` for details.

import Crypto

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLDSA65.PrivateKey {
    /// Generate a signature for the prehashed message representative (a.k.a. "external mu").
    ///
    /// > Note: The message representative should be obtained via calls to ``MLDSA65/PublicKey/prehash(for:context:)``.
    ///
    /// - Parameter mu: The prehashed message representative (a.k.a. "external mu").
    ///
    /// - Returns: The signature of the prehashed message representative.
    public func signature(forPrehashedMessageRepresentative mu: some DataProtocol) throws -> Data {
        try self.signature_boring(forPrehashedMessageRepresentative: mu)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLDSA65.PublicKey {
    /// Generate a prehashed message representative (a.k.a. "external mu") for the given message.
    ///
    /// - Parameter data: The message to prehash.
    ///
    /// - Returns: The prehashed message representative (a.k.a. "external mu").
    public func prehash<D: DataProtocol>(for data: D) throws -> Data {
        try self.prehash_boring(for: data)
    }

    /// Generate a prehashed message representative (a.k.a. "external mu") for the given message.
    ///
    /// - Parameters:
    ///   - data: The message to prehash.
    ///   - context: The context of the message.
    ///
    /// - Returns: The prehashed message representative (a.k.a. "external mu").
    public func prehash<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data {
        try self.prehash_boring(for: data, context: context)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLDSA87.PrivateKey {
    /// Generate a signature for the prehashed message representative (a.k.a. "external mu").
    ///
    /// > Note: The message representative should be obtained via calls to ``MLDSA87/PublicKey/prehash(for:context:)``.
    ///
    /// - Parameter mu: The prehashed message representative (a.k.a. "external mu").
    ///
    /// - Returns: The signature of the prehashed message representative.
    public func signature(forPrehashedMessageRepresentative mu: some DataProtocol) throws -> Data {
        try self.signature_boring(forPrehashedMessageRepresentative: mu)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLDSA87.PublicKey {
    /// Generate a prehashed message representative (a.k.a. "external mu") for the given message.
    ///
    /// - Parameter data: The message to prehash.
    ///
    /// - Returns: The prehashed message representative (a.k.a. "external mu").
    public func prehash<D: DataProtocol>(for data: D) throws -> Data {
        try self.prehash_boring(for: data)
    }

    /// Generate a prehashed message representative (a.k.a. "external mu") for the given message.
    ///
    /// - Parameters:
    ///   - data: The message to prehash.
    ///   - context: The context of the message.
    ///
    /// - Returns: The prehashed message representative (a.k.a. "external mu").
    public func prehash<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data {
        try self.prehash_boring(for: data, context: context)
    }
}
