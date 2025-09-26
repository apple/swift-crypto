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

#if CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
public import SwiftSystem
#else
#if canImport(FoundationEssentials)
public import FoundationEssentials
#else
public import Foundation
#endif
#endif

/// A key encapsulation mechanism.
///
/// Use a key encapsulation mechanism (KEM) to protect a symmetric cryptographic key that you share with another party.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public enum KEM: Sendable {
    /// The result of a key encapsulation operation.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public struct EncapsulationResult: Sendable {
        /// The shared secret.
        public let sharedSecret: SymmetricKey
        /// The encapsulated representation of the shared secret.
        public let encapsulated: Data
        
        /// Initializes a key encapsulation result.
        public init(sharedSecret: SymmetricKey, encapsulated: Data) {
            self.sharedSecret = sharedSecret
            self.encapsulated = encapsulated
        }
    }
}

/// The public key for a key encapsulation mechanism.
@preconcurrency
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public protocol KEMPublicKey: Sendable {
    /// Generates and encapsulates a shared secret.
    ///
    /// Share the encapsulated secret with the person who has the ``KEMPrivateKey``.
    /// They use ``KEMPrivateKey/decapsulate(_:)`` to recover the shared secret.
    /// - Returns: The shared secret, and its encapsulated version.
    func encapsulate() throws -> KEM.EncapsulationResult
}

/// The private key for a key encapsulation mechanism.
@preconcurrency
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public protocol KEMPrivateKey: Sendable {
    associatedtype PublicKey: KEMPublicKey
    
    /// Generates a new random private key.
    /// - Returns: The generated private key.
    ///
    /// Give the ``publicKey`` to another person so that they can encapsulate
    /// shared secrets that you recover by calling ``decapsulate(_:)``.
    static func generate() throws -> Self
    
    /// Recovers a shared secret from an encapsulated representation.
    /// - Parameter encapsulated: The encapsulated shared secret that someone created using this key's ``publicKey``.
    /// - Returns: The decapsulated shared secret.
    func decapsulate(_ encapsulated: Data) throws -> SymmetricKey
    
    /// The associated public key.
    var publicKey: PublicKey { get }
}
#endif // Linux or !SwiftPM
