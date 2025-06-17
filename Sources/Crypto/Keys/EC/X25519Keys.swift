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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Curve25519.KeyAgreement {
    static var keyByteCount: Int {
        return 32
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Curve25519 {
    /// A mechanism used to create a shared secret between two users by
    /// performing X25519 key agreement.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum KeyAgreement: Sendable {
        #if (!CRYPTO_IN_SWIFTPM_FORCE_BUILD_API) || CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
        typealias Curve25519PrivateKeyImpl = Curve25519.KeyAgreement.CoreCryptoCurve25519PrivateKeyImpl
        typealias Curve25519PublicKeyImpl = Curve25519.KeyAgreement.CoreCryptoCurve25519PublicKeyImpl
        #else
        typealias Curve25519PrivateKeyImpl = Curve25519.KeyAgreement.OpenSSLCurve25519PrivateKeyImpl
        typealias Curve25519PublicKeyImpl = Curve25519.KeyAgreement.OpenSSLCurve25519PublicKeyImpl
        #endif

        /// A Curve25519 public key used for key agreement.
        @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
        public struct PublicKey: ECPublicKey, Sendable {
            fileprivate var baseKey: Curve25519PublicKeyImpl

            /// Creates a Curve25519 public key for key agreement from a
            /// collection of bytes.
            ///
            /// - Parameters:
            /// - rawRepresentation: A raw representation of the key as a
            /// collection of contiguous bytes.
            public init<D: ContiguousBytes>(rawRepresentation: D) throws(CryptoKitMetaError) {
                self.baseKey = try Curve25519PublicKeyImpl(rawRepresentation: rawRepresentation)
            }

            fileprivate init(baseKey: Curve25519PublicKeyImpl) {
                self.baseKey = baseKey
            }

            /// A representation of the Curve25519 public key as a collection of
            /// bytes.
            public var rawRepresentation: Data {
                return self.baseKey.rawRepresentation
            }

            var keyBytes: [UInt8] {
                return self.baseKey.keyBytes
            }

            #if hasFeature(Embedded)
            private func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
                return try self.baseKey.keyBytes.withUnsafeBytes(body)
            }
            #else
            private func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
                return try self.baseKey.keyBytes.withUnsafeBytes(body)
            }
            #endif
        }

        /// A Curve25519 private key used for key agreement.
        @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
        public struct PrivateKey: DiffieHellmanKeyAgreement, Sendable {
            fileprivate var baseKey: Curve25519PrivateKeyImpl

            /// Creates a random Curve25519 private key for key agreement.
            public init() {
                self.baseKey = Curve25519PrivateKeyImpl()
            }

            /// The corresponding public key.
            public var publicKey: Curve25519.KeyAgreement.PublicKey {
                return PublicKey(baseKey: self.baseKey.publicKey)
            }

            /// Creates a Curve25519 private key for key agreement from a
            /// collection of bytes.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A raw representation of the key as a
            /// collection of contiguous bytes.
            public init<D: ContiguousBytes>(rawRepresentation: D) throws(CryptoKitMetaError) {
                self.baseKey = try Curve25519PrivateKeyImpl(rawRepresentation: rawRepresentation)
            }

            /// Computes a shared secret with the provided public key from
            /// another party.
            ///
            /// - Parameters:
            ///   - publicKeyShare: The public key from another party to be
            /// combined with the private key from this user to create the
            /// shared secret.
            ///
            /// - Returns: The computed shared secret.
            public func sharedSecretFromKeyAgreement(with publicKeyShare: Curve25519.KeyAgreement.PublicKey) throws(CryptoKitMetaError) -> SharedSecret {
                return try self.baseKey.sharedSecretFromKeyAgreement(with: publicKeyShare.baseKey)
            }
            
            /// The raw representation of the key as a collection of contiguous
            /// bytes.
            public var rawRepresentation: Data {
                return self.baseKey.rawRepresentation
            }

            var key: SecureBytes {
                return self.baseKey.key
            }
        }
    }
}
#endif // Linux or !SwiftPM
