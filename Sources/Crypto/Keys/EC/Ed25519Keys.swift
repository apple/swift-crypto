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
extension Curve25519.Signing {
    static var keyByteCount: Int {
        return 32
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Curve25519 {
    /// A mechanism used to create or verify a cryptographic signature using
    /// Ed25519.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum Signing: Sendable {
        #if (!CRYPTO_IN_SWIFTPM_FORCE_BUILD_API) || CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
        typealias Curve25519PrivateKeyImpl = Curve25519.Signing.CoreCryptoCurve25519PrivateKeyImpl
        typealias Curve25519PublicKeyImpl = Curve25519.Signing.CoreCryptoCurve25519PublicKeyImpl
        #else
        typealias Curve25519PrivateKeyImpl = Curve25519.Signing.OpenSSLCurve25519PrivateKeyImpl
        typealias Curve25519PublicKeyImpl = Curve25519.Signing.OpenSSLCurve25519PublicKeyImpl
        #endif

        /// A Curve25519 private key used to create cryptographic signatures.
        @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
        public struct PrivateKey: ECPrivateKey, Sendable {
            private var baseKey: Curve25519.Signing.Curve25519PrivateKeyImpl
            
            /// Creates a random Curve25519 private key for signing.
            public init() {
                self.baseKey = Curve25519.Signing.Curve25519PrivateKeyImpl()
            }

            /// The corresponding public key.
            public var publicKey: PublicKey {
                return PublicKey(baseKey: self.baseKey.publicKey)
            }

            /// Creates a Curve25519 private key for signing from a data
            /// representation.
            ///
            /// - Parameters:
            ///   - data: A representation of the key as contiguous bytes from
            /// which to create the key.
            public init<D: ContiguousBytes>(rawRepresentation data: D) throws(CryptoKitMetaError) {
                self.baseKey = try Curve25519.Signing.Curve25519PrivateKeyImpl(rawRepresentation: data)
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

        /// A Curve25519 public key used to verify cryptographic signatures.
        @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
        public struct PublicKey: Sendable {
            private var baseKey: Curve25519.Signing.Curve25519PublicKeyImpl

            /// Creates a Curve25519 public key from a data representation.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A representation of the key as contiguous
            /// bytes from which to create the key.
            public init<D: ContiguousBytes>(rawRepresentation: D) throws(CryptoKitMetaError) {
                self.baseKey = try Curve25519.Signing.Curve25519PublicKeyImpl(rawRepresentation: rawRepresentation)
            }

            fileprivate init(baseKey: Curve25519.Signing.Curve25519PublicKeyImpl) {
                self.baseKey = baseKey
            }

            /// A representation of the public key.
            public var rawRepresentation: Data {
                return self.baseKey.rawRepresentation
            }

            var keyBytes: [UInt8] {
                return self.baseKey.keyBytes
            }
        }
    }
}
#endif // Linux or !SwiftPM
