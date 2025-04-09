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
@_implementationOnly import CCryptoBoringSSLShims
import CryptoBoringWrapper
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLAEAD {
    /// Seal a given message.
    func seal<Plaintext: DataProtocol, Nonce: ContiguousBytes, AuthenticatedData: DataProtocol>(
        message: Plaintext,
        key: SymmetricKey,
        nonce: Nonce,
        authenticatedData: AuthenticatedData
    ) throws -> (ciphertext: Data, tag: Data) {
        do {
            let context = try AEADContext(cipher: self, key: key)
            return try context.seal(
                message: message,
                nonce: nonce,
                authenticatedData: authenticatedData
            )
        } catch CryptoBoringWrapperError.underlyingCoreCryptoError(let errorCode) {
            throw CryptoKitError.underlyingCoreCryptoError(error: errorCode)
        }
    }

    /// Open a given message.
    func open<Nonce: ContiguousBytes, AuthenticatedData: DataProtocol>(
        ciphertext: Data,
        key: SymmetricKey,
        nonce: Nonce,
        tag: Data,
        authenticatedData: AuthenticatedData
    ) throws -> Data {
        do {
            let context = try AEADContext(cipher: self, key: key)
            return try context.open(
                ciphertext: ciphertext,
                nonce: nonce,
                tag: tag,
                authenticatedData: authenticatedData
            )
        } catch CryptoBoringWrapperError.underlyingCoreCryptoError(let errorCode) {
            throw CryptoKitError.underlyingCoreCryptoError(error: errorCode)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
enum OpenSSLChaChaPolyImpl {
    static func encrypt<M: DataProtocol, AD: DataProtocol>(
        key: SymmetricKey,
        message: M,
        nonce: ChaChaPoly.Nonce?,
        authenticatedData: AD?
    ) throws -> ChaChaPoly.SealedBox {
        guard key.bitCount == ChaChaPoly.keyBitsCount else {
            throw CryptoKitError.incorrectKeySize
        }
        let nonce = nonce ?? ChaChaPoly.Nonce()

        let ciphertext: Data
        let tag: Data
        if let ad = authenticatedData {
            (ciphertext, tag) = try BoringSSLAEAD.chacha20.seal(
                message: message,
                key: key,
                nonce: nonce,
                authenticatedData: ad
            )
        } else {
            (ciphertext, tag) = try BoringSSLAEAD.chacha20.seal(
                message: message,
                key: key,
                nonce: nonce,
                authenticatedData: []
            )
        }

        return try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
    }

    static func decrypt<AD: DataProtocol>(
        key: SymmetricKey,
        ciphertext: ChaChaPoly.SealedBox,
        authenticatedData: AD?
    ) throws -> Data {
        guard key.bitCount == ChaChaPoly.keyBitsCount else {
            throw CryptoKitError.incorrectKeySize
        }

        if let ad = authenticatedData {
            return try BoringSSLAEAD.chacha20.open(
                ciphertext: ciphertext.ciphertext,
                key: key,
                nonce: ciphertext.nonce,
                tag: ciphertext.tag,
                authenticatedData: ad
            )
        } else {
            return try BoringSSLAEAD.chacha20.open(
                ciphertext: ciphertext.ciphertext,
                key: key,
                nonce: ciphertext.nonce,
                tag: ciphertext.tag,
                authenticatedData: []
            )
        }
    }
}
#endif  // CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
