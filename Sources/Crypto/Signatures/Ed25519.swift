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
protocol DigestValidator {
    associatedtype Signature
    func isValidSignature<D: Digest>(_ signature: Signature, for digest: D) -> Bool
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
protocol DataValidator {
    associatedtype Signature
    func isValidSignature<D: DataProtocol>(_ signature: Signature, for signedData: D) -> Bool
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Curve25519.Signing {
    static var signatureByteCount: Int {
        return 64
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Curve25519.Signing.PublicKey: DataValidator {
    typealias Signature = Data
    
    /// Verifies an EdDSA signature over Curve25519.
    ///
    /// - Parameters:
    ///   - signature: The signature to check against the given data.
    ///   - data: The data covered by the signature.
    ///
    /// - Returns: A Boolean value that’s `true` when the signature is valid for
    /// the given data.
    public func isValidSignature<S: DataProtocol, D: DataProtocol>(_ signature: S, for data: D) -> Bool {
        #if (!CRYPTO_IN_SWIFTPM_FORCE_BUILD_API) || CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
        return self.coreCryptoIsValidSignature(signature, for: data)
        #else
        return self.openSSLIsValidSignature(signature, for: data)
        #endif
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Curve25519.Signing.PrivateKey: Signer {
    /// Generates an EdDSA signature over Curve25519.
    ///
    /// - Parameters:
    ///   - data: The data to sign.
    ///
    /// - Returns: The signature for the data. Although not required by [RFC
    /// 8032](https://tools.ietf.org/html/rfc8032), which describes the
    /// Edwards-Curve Digital Signature Algorithm (EdDSA), the CryptoKit
    /// implementation of the algorithm employs randomization to generate a
    /// different signature on every call, even for the same data and key, to
    /// guard against side-channel attacks.
    public func signature<D: DataProtocol>(for data: D) throws(CryptoKitMetaError) -> Data {
        #if (!CRYPTO_IN_SWIFTPM_FORCE_BUILD_API) || CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
        return try self.coreCryptoSignature(for: data)
        #else
        return try self.openSSLSignature(for: data)
        #endif
    }
}
#endif // Linux or !SwiftPM
