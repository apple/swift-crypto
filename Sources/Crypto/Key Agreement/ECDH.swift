//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
typealias NISTCurvePublicKeyImpl = CoreCryptoNISTCurvePublicKeyImpl
typealias NISTCurvePrivateKeyImpl = CoreCryptoNISTCurvePrivateKeyImpl
#else
typealias NISTCurvePublicKeyImpl = OpenSSLNISTCurvePublicKeyImpl
typealias NISTCurvePrivateKeyImpl = OpenSSLNISTCurvePrivateKeyImpl
#endif

import Foundation

extension P256 {
    public enum Signing {
        public struct PublicKey: NISTECPublicKey {
            var impl: NISTCurvePublicKeyImpl<P256.CurveDetails>

            public init<D: ContiguousBytes>(rawRepresentation: D) throws {
                impl = try NISTCurvePublicKeyImpl(rawRepresentation: rawRepresentation)
            }

            public init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(compactRepresentation: compactRepresentation)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(x963Representation: x963Representation)
            }

            init(impl: NISTCurvePublicKeyImpl<P256.CurveDetails>) {
                self.impl = impl
            }

            public var compactRepresentation: Data? { impl.compactRepresentation }
            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }
        }

        public struct PrivateKey: NISTECPrivateKey {
            let impl: NISTCurvePrivateKeyImpl<P256.CurveDetails>

            public init(compactRepresentable: Bool = true) {
                impl = NISTCurvePrivateKeyImpl(compactRepresentable: compactRepresentable)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(x963: x963Representation)
            }

            public init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(data: rawRepresentation)
            }

            init(impl: NISTCurvePrivateKeyImpl<P256.CurveDetails>) {
                self.impl = impl
            }

            public var publicKey: P256.Signing.PublicKey {
                return PublicKey(impl: impl.publicKey())
            }

            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }
        }
    }
}

extension P256 {
    public enum KeyAgreement {
        public struct PublicKey: NISTECPublicKey {
            var impl: NISTCurvePublicKeyImpl<P256.CurveDetails>

            public init<D: ContiguousBytes>(rawRepresentation: D) throws {
                impl = try NISTCurvePublicKeyImpl(rawRepresentation: rawRepresentation)
            }

            public init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(compactRepresentation: compactRepresentation)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(x963Representation: x963Representation)
            }

            init(impl: NISTCurvePublicKeyImpl<P256.CurveDetails>) {
                self.impl = impl
            }

            public var compactRepresentation: Data? { impl.compactRepresentation }
            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }
        }

        public struct PrivateKey: NISTECPrivateKey {
            let impl: NISTCurvePrivateKeyImpl<P256.CurveDetails>

            public init(compactRepresentable: Bool = true) {
                impl = NISTCurvePrivateKeyImpl(compactRepresentable: compactRepresentable)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(x963: x963Representation)
            }

            public init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(data: rawRepresentation)
            }

            init(impl: NISTCurvePrivateKeyImpl<P256.CurveDetails>) {
                self.impl = impl
            }

            public var publicKey: P256.KeyAgreement.PublicKey {
                return PublicKey(impl: impl.publicKey())
            }

            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }
        }
    }
}

extension P384 {
    public enum Signing {
        public struct PublicKey: NISTECPublicKey {
            var impl: NISTCurvePublicKeyImpl<P384.CurveDetails>

            public init<D: ContiguousBytes>(rawRepresentation: D) throws {
                impl = try NISTCurvePublicKeyImpl(rawRepresentation: rawRepresentation)
            }

            public init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(compactRepresentation: compactRepresentation)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(x963Representation: x963Representation)
            }

            init(impl: NISTCurvePublicKeyImpl<P384.CurveDetails>) {
                self.impl = impl
            }

            public var compactRepresentation: Data? { impl.compactRepresentation }
            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }
        }

        public struct PrivateKey: NISTECPrivateKey {
            let impl: NISTCurvePrivateKeyImpl<P384.CurveDetails>

            public init(compactRepresentable: Bool = true) {
                impl = NISTCurvePrivateKeyImpl(compactRepresentable: compactRepresentable)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(x963: x963Representation)
            }

            public init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(data: rawRepresentation)
            }

            init(impl: NISTCurvePrivateKeyImpl<P384.CurveDetails>) {
                self.impl = impl
            }

            public var publicKey: P384.Signing.PublicKey {
                return PublicKey(impl: impl.publicKey())
            }

            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }
        }
    }
}

extension P384 {
    public enum KeyAgreement {
        public struct PublicKey: NISTECPublicKey {
            var impl: NISTCurvePublicKeyImpl<P384.CurveDetails>

            public init<D: ContiguousBytes>(rawRepresentation: D) throws {
                impl = try NISTCurvePublicKeyImpl(rawRepresentation: rawRepresentation)
            }

            public init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(compactRepresentation: compactRepresentation)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(x963Representation: x963Representation)
            }

            init(impl: NISTCurvePublicKeyImpl<P384.CurveDetails>) {
                self.impl = impl
            }

            public var compactRepresentation: Data? { impl.compactRepresentation }
            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }
        }

        public struct PrivateKey: NISTECPrivateKey {
            let impl: NISTCurvePrivateKeyImpl<P384.CurveDetails>

            public init(compactRepresentable: Bool = true) {
                impl = NISTCurvePrivateKeyImpl(compactRepresentable: compactRepresentable)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(x963: x963Representation)
            }

            public init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(data: rawRepresentation)
            }

            init(impl: NISTCurvePrivateKeyImpl<P384.CurveDetails>) {
                self.impl = impl
            }

            public var publicKey: P384.KeyAgreement.PublicKey {
                return PublicKey(impl: impl.publicKey())
            }

            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }
        }
    }
}

extension P521 {
    public enum Signing {
        public struct PublicKey: NISTECPublicKey {
            var impl: NISTCurvePublicKeyImpl<P521.CurveDetails>

            public init<D: ContiguousBytes>(rawRepresentation: D) throws {
                impl = try NISTCurvePublicKeyImpl(rawRepresentation: rawRepresentation)
            }

            public init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(compactRepresentation: compactRepresentation)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(x963Representation: x963Representation)
            }

            init(impl: NISTCurvePublicKeyImpl<P521.CurveDetails>) {
                self.impl = impl
            }

            public var compactRepresentation: Data? { impl.compactRepresentation }
            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }
        }

        public struct PrivateKey: NISTECPrivateKey {
            let impl: NISTCurvePrivateKeyImpl<P521.CurveDetails>

            public init(compactRepresentable: Bool = true) {
                impl = NISTCurvePrivateKeyImpl(compactRepresentable: compactRepresentable)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(x963: x963Representation)
            }

            public init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(data: rawRepresentation)
            }

            init(impl: NISTCurvePrivateKeyImpl<P521.CurveDetails>) {
                self.impl = impl
            }

            public var publicKey: P521.Signing.PublicKey {
                return PublicKey(impl: impl.publicKey())
            }

            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }
        }
    }
}

extension P521 {
    public enum KeyAgreement {
        public struct PublicKey: NISTECPublicKey {
            var impl: NISTCurvePublicKeyImpl<P521.CurveDetails>

            public init<D: ContiguousBytes>(rawRepresentation: D) throws {
                impl = try NISTCurvePublicKeyImpl(rawRepresentation: rawRepresentation)
            }

            public init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(compactRepresentation: compactRepresentation)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(x963Representation: x963Representation)
            }

            init(impl: NISTCurvePublicKeyImpl<P521.CurveDetails>) {
                self.impl = impl
            }

            public var compactRepresentation: Data? { impl.compactRepresentation }
            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }
        }

        public struct PrivateKey: NISTECPrivateKey {
            let impl: NISTCurvePrivateKeyImpl<P521.CurveDetails>

            public init(compactRepresentable: Bool = true) {
                impl = NISTCurvePrivateKeyImpl(compactRepresentable: compactRepresentable)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(x963: x963Representation)
            }

            public init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(data: rawRepresentation)
            }

            init(impl: NISTCurvePrivateKeyImpl<P521.CurveDetails>) {
                self.impl = impl
            }

            public var publicKey: P521.KeyAgreement.PublicKey {
                return PublicKey(impl: impl.publicKey())
            }

            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }
        }
    }
}

extension P256.KeyAgreement.PrivateKey: DiffieHellmanKeyAgreement {
    /// Performs a key agreement with provided public key share.
    ///
    /// - Parameter publicKeyShare: The public key to perform the ECDH with.
    /// - Returns: Returns a shared secret
    /// - Throws: An error occured while computing the shared secret
    public func sharedSecretFromKeyAgreement(with publicKeyShare: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        #if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        return try self.coreCryptoSharedSecretFromKeyAgreement(with: publicKeyShare)
        #else
        return try self.openSSLSharedSecretFromKeyAgreement(with: publicKeyShare)
        #endif
    }
}
extension P384.KeyAgreement.PrivateKey: DiffieHellmanKeyAgreement {
    /// Performs a key agreement with provided public key share.
    ///
    /// - Parameter publicKeyShare: The public key to perform the ECDH with.
    /// - Returns: Returns a shared secret
    /// - Throws: An error occured while computing the shared secret
    public func sharedSecretFromKeyAgreement(with publicKeyShare: P384.KeyAgreement.PublicKey) throws -> SharedSecret {
        #if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        return try self.coreCryptoSharedSecretFromKeyAgreement(with: publicKeyShare)
        #else
        return try self.openSSLSharedSecretFromKeyAgreement(with: publicKeyShare)
        #endif
    }
}
extension P521.KeyAgreement.PrivateKey: DiffieHellmanKeyAgreement {
    /// Performs a key agreement with provided public key share.
    ///
    /// - Parameter publicKeyShare: The public key to perform the ECDH with.
    /// - Returns: Returns a shared secret
    /// - Throws: An error occured while computing the shared secret
    public func sharedSecretFromKeyAgreement(with publicKeyShare: P521.KeyAgreement.PublicKey) throws -> SharedSecret {
        #if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        return try self.coreCryptoSharedSecretFromKeyAgreement(with: publicKeyShare)
        #else
        return try self.openSSLSharedSecretFromKeyAgreement(with: publicKeyShare)
        #endif
    }
}
#endif // Linux or !SwiftPM
