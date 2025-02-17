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
import FoundationEssentials
#else
import Foundation
#endif

/// A Key Encapsulation Mechanism
public enum KEM {
    /// The result of an encapsulation operation
    public struct EncapsulationResult {
        /// The shared secret
        public let sharedSecret: SymmetricKey
        /// The encapsulated secret
        public let encapsulated: Data
        
        public init(sharedSecret: SymmetricKey, encapsulated: Data) {
            self.sharedSecret = sharedSecret
            self.encapsulated = encapsulated
        }
    }
}

/// A Key Encapsulation Mechanism's Public Key
public protocol KEMPublicKey {
    /// Encapsulates the generated shared secret
    /// - Returns: The shared secret and its encapsulated version
    func encapsulate() throws -> KEM.EncapsulationResult
}

/// A Key Encapsulation Mechanism's Private Key
public protocol KEMPrivateKey {
    associatedtype PublicKey: KEMPublicKey
    
    /// Generate a new random Private Key
    /// - Returns: The generated private key
    static func generate() throws -> Self
    
    /// Decapsulates the encapsulated shared secret
    /// - Parameter encapsulated: The encapsulated shared secret
    /// - Returns: The decapsulated shared secret
    func decapsulate(_ encapsulated: Data) throws -> SymmetricKey
    
    /// Returns the associated public key
    var publicKey: PublicKey { get }
}
#endif // Linux or !SwiftPM
