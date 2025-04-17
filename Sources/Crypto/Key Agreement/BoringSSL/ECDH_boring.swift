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
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
@_implementationOnly import CCryptoBoringSSL

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P256.KeyAgreement.PrivateKey {
    internal func openSSLSharedSecretFromKeyAgreement(
        with publicKeyShare: P256.KeyAgreement.PublicKey
    ) throws -> SharedSecret {
        let key = try self.impl.key.keyExchange(publicKey: publicKeyShare.impl.key)
        return SharedSecret(ss: key)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P384.KeyAgreement.PrivateKey {
    internal func openSSLSharedSecretFromKeyAgreement(
        with publicKeyShare: P384.KeyAgreement.PublicKey
    ) throws -> SharedSecret {
        let key = try self.impl.key.keyExchange(publicKey: publicKeyShare.impl.key)
        return SharedSecret(ss: key)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P521.KeyAgreement.PrivateKey {
    internal func openSSLSharedSecretFromKeyAgreement(
        with publicKeyShare: P521.KeyAgreement.PublicKey
    ) throws -> SharedSecret {
        let key = try self.impl.key.keyExchange(publicKey: publicKeyShare.impl.key)
        return SharedSecret(ss: key)
    }
}
#endif  // CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
