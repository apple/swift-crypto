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
#if CRYPTOKIT_STATIC_LIBRARY
@_exported import CryptoKit_Static
#else
@_exported import CryptoKit
#endif
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
#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, macCatalyst 17.0, *)
#else //CRYPTOKIT_STATIC_LIBRARY
@available(iOS 16.0, macOS 10.13, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 1.0, *)
#endif
public enum KEM: Sendable {
    /// The result of a key encapsulation operation.
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
#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, macCatalyst 17.0, *)
#else //CRYPTOKIT_STATIC_LIBRARY
@available(iOS 16.0, macOS 10.13, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 1.0, *)
#endif
@preconcurrency
public protocol KEMPublicKey: Sendable {
    /// Generates and encapsulates a shared secret.
    ///
    /// Share the encapsulated secret with the person who has the ``KEMPrivateKey``.
    /// They use ``KEMPrivateKey/decapsulate(_:)`` to recover the shared secret.
    /// - Returns: The shared secret, and its encapsulated version.
    func encapsulate() throws -> KEM.EncapsulationResult
}

/// The private key for a key encapsulation mechanism.
#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 17.0, macOS 14.0, watchOS 10.0, tvOS 17.0, macCatalyst 17.0, *)
#else //CRYPTOKIT_STATIC_LIBRARY
@available(iOS 16.0, macOS 10.13, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 1.0, *)
#endif
@preconcurrency
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

/// A one-time private key for a key encapsulation mechanism, which can only decapsulate once but it does so faster.
@available(iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0, macCatalyst 27.0, visionOS 27.0, *)
@preconcurrency
public protocol KEMOneTimePrivateKey: ~Copyable, Sendable {
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
    consuming func decapsulate(_ encapsulated: Data) throws -> SymmetricKey

    /// The associated public key.
    var publicKey: PublicKey { get }
}
#endif // Linux or !SwiftPM
