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

/// A Diffie-Hellman Key Agreement Key
@preconcurrency
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public protocol DiffieHellmanKeyAgreement: Sendable {
    /// The public key share type to perform the DH Key Agreement
    associatedtype PublicKey: Sendable
    var publicKey: PublicKey { get }

    /// Performs a Diffie-Hellman Key Agreement.
    ///
    /// - Parameters:
    ///   - publicKeyShare: The public key share.
    /// - Returns: The resulting key agreement result.
    func sharedSecretFromKeyAgreement(with publicKeyShare: PublicKey) throws(CryptoKitMetaError) -> SharedSecret
}

/// A key agreement result from which you can derive a symmetric cryptographic
/// key.
///
/// Generate a shared secret by calling your private key’s
/// `sharedSecretFromKeyAgreement(publicKeyShare:)` method with the public key
/// from another party. The other party computes the same secret by passing your
/// public key to the the equivalent method on their own private key.
///
/// The shared secret isn’t suitable as a symmetric cryptographic key
/// (``SymmetricKey``) by itself. However, you use it to generate a key by
/// calling either the
/// ``hkdfDerivedSymmetricKey(using:salt:sharedInfo:outputByteCount:)`` or
/// ``x963DerivedSymmetricKey(using:sharedInfo:outputByteCount:)`` method of the
/// shared secret. After the other party does the same, then you both share a
/// symmetric key suitable for creating a message authentication code like
/// ``HMAC``, or for opening and closing a sealed box with a cipher like
/// ``ChaChaPoly`` or ``AES``.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct SharedSecret: ContiguousBytes, Sendable {
    var ss: SecureBytes
    
    internal init(ss: SecureBytes){
        self.ss = ss
    }
    
    /// Invokes the given closure with a buffer pointer covering the raw bytes
    /// of the shared secret.
    ///
    /// - Parameters:
    ///   - body: A closure that takes a raw buffer pointer to the bytes of the
    /// shared secret and returns the shared secret.
    ///
    /// - Returns: The shared secret, as returned from the body closure.
    #if hasFeature(Embedded)
    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        return try ss.withUnsafeBytes(body)
    }
    #else
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try ss.withUnsafeBytes(body)
    }
    #endif

    /// Derives a symmetric encryption key from the secret using x9.63 key
    /// derivation.
    ///
    /// - Parameters:
    ///   - hashFunction: The hash function to use for key derivation.
    ///   - sharedInfo: The shared information to use for key derivation.
    ///   - outputByteCount: The length in bytes of resulting symmetric key.
    ///
    /// - Returns: The derived symmetric key.
    public func x963DerivedSymmetricKey<H: HashFunction, SI: DataProtocol>(using hashFunction: H.Type, sharedInfo: SI, outputByteCount: Int) -> SymmetricKey {
        
        return self.ss.withUnsafeBytes { ssBytes in
            return ANSIKDFx963<H>.deriveKey(inputKeyMaterial: SymmetricKey(data: ssBytes), info: sharedInfo, outputByteCount: outputByteCount)
        }
    }

    /// Derives a symmetric encryption key from the secret using HKDF key
    /// derivation.
    ///
    /// - Parameters:
    ///   - hashFunction: The hash function to use for key derivation.
    ///   - salt: The salt to use for key derivation.
    ///   - sharedInfo: The shared information to use for key derivation.
    ///   - outputByteCount: The length in bytes of resulting symmetric key.
    ///
    /// - Returns: The derived symmetric key.
    public func hkdfDerivedSymmetricKey<H: HashFunction, Salt: DataProtocol, SI: DataProtocol>(using hashFunction: H.Type, salt: Salt, sharedInfo: SI, outputByteCount: Int) -> SymmetricKey {
        #if os(iOS) && (arch(arm) || arch(i386))
        fatalError("Unsupported architecture")
        #else
        return HKDF<H>.deriveKey(inputKeyMaterial: SymmetricKey(data: ss), salt: salt, info: sharedInfo, outputByteCount: outputByteCount)
        #endif
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SharedSecret: Hashable {
    public func hash(into hasher: inout Hasher) {
        ss.withUnsafeBytes { hasher.combine(bytes: $0) }
    }
}

// We want to implement constant-time comparison for digests.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SharedSecret: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        return safeCompare(lhs, rhs)
    }
    
    /// Determines whether a shared secret is equivalent to a collection of
    /// contiguous bytes.
    ///
    /// - Parameters:
    ///   - lhs: The shared secret to compare.
    ///   - rhs: A collection of contiguous bytes to compare.
    ///
    /// - Returns: A Boolean value that’s `true` if the shared secret and the
    /// collection of binary data are equivalent.
    public static func == <D: DataProtocol>(lhs: Self, rhs: D) -> Bool {
        if rhs.regions.count != 1 {
            let rhsContiguous = Data(rhs)
            return safeCompare(lhs, rhsContiguous)
        } else {
            return safeCompare(lhs, rhs.regions.first!)
        }
    }
}

#if !hasFeature(Embedded)
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SharedSecret: CustomStringConvertible {
    public var description: String {
        return "\(Self.self): \(ss.hexString)"
    }
}
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension HashFunction {
    // A wrapper function to keep the unsafe code in one place.
    mutating func update(_ secret: SharedSecret) {
        secret.withUnsafeBytes {
            self.update(bufferPointer: $0)
        }
    }
    mutating func update(_ counter: UInt32) {
        withUnsafeBytes(of: counter) {
            self.update(bufferPointer: $0)
        }
    }
}

#endif // Linux or !SwiftPM
