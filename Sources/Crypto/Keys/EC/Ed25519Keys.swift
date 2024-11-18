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
import Foundation

extension Curve25519.Signing {
    static var keyByteCount: Int {
        return 32
    }
}

extension Curve25519 {
    /// A mechanism used to create or verify a cryptographic signature using
    /// Ed25519.
    public enum Signing {
        #if !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        typealias Curve25519PrivateKeyImpl = Curve25519.Signing.CoreCryptoCurve25519PrivateKeyImpl
        typealias Curve25519PublicKeyImpl = Curve25519.Signing.CoreCryptoCurve25519PublicKeyImpl
        #else
        typealias Curve25519PrivateKeyImpl = Curve25519.Signing.OpenSSLCurve25519PrivateKeyImpl
        typealias Curve25519PublicKeyImpl = Curve25519.Signing.OpenSSLCurve25519PublicKeyImpl
        #endif

        /// A Curve25519 private key used to create cryptographic signatures.
        public struct PrivateKey: ECPrivateKey {
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
            public init<D: ContiguousBytes>(rawRepresentation data: D) throws {
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
        public struct PublicKey {
            private var baseKey: Curve25519.Signing.Curve25519PublicKeyImpl

            /// Creates a Curve25519 public key from a data representation.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A representation of the key as contiguous
            /// bytes from which to create the key.
            public init<D: ContiguousBytes>(rawRepresentation: D) throws {
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
