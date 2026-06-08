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
    ) throws -> Data {
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

    /// Seal a given message in place
    #if swift(<6.3)
    @_lifetime(message: copy message)
    #endif
    func seal(
        message: inout MutableRawSpan,
        key: SymmetricKey,
        nonce: RawSpan,
        authenticatedData: RawSpan,
        tag: inout OutputRawSpan
    ) throws {
        do {
            let context = try AEADContext(cipher: self, key: key)
            return try context.seal(
                message: &message,
                nonce: nonce,
                authenticatedData: authenticatedData,
                tag: &tag,
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

    /// Open a given message in place.
    #if swift(<6.3)
    @_lifetime(message: copy message)
    #endif
    public func open(
        message: inout MutableRawSpan,
        key: SymmetricKey,
        nonce: RawSpan,
        tag: RawSpan,
        authenticatedData: RawSpan
    ) throws {
        do {
            let context = try AEADContext(cipher: self, key: key)
            return try context.open(
                message: &message,
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

        let combined: Data
        if let ad = authenticatedData {
            combined = try BoringSSLAEAD.chacha20.seal(
                message: message,
                key: key,
                nonce: nonce,
                authenticatedData: ad
            )
        } else {
            combined = try BoringSSLAEAD.chacha20.seal(
                message: message,
                key: key,
                nonce: nonce,
                authenticatedData: []
            )
        }

        return ChaChaPoly.SealedBox(combined: combined, nonceByteCount: nonce.count)
    }

    #if swift(<6.3)
    @_lifetime(message: copy message)
    #endif
    static func encrypt(
        key: SymmetricKey,
        inPlace message: inout MutableRawSpan,
        nonce: RawSpan,
        authenticatedData: RawSpan?,
        tag: inout OutputRawSpan
    ) throws {
        guard key.bitCount == ChaChaPoly.keyBitsCount else {
            throw CryptoKitError.incorrectKeySize
        }

        if let ad = authenticatedData {
            try BoringSSLAEAD.chacha20.seal(
                message: &message,
                key: key,
                nonce: nonce,
                authenticatedData: ad,
                tag: &tag
            )
        } else {
            try BoringSSLAEAD.chacha20.seal(
                message: &message,
                key: key,
                nonce: nonce,
                authenticatedData: RawSpan(),
                tag: &tag
            )
        }
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

    #if swift(<6.3)
    @_lifetime(message: copy message)
    #endif
    static func decrypt(
        key: SymmetricKey,
        inPlace message: inout MutableRawSpan,
        nonce: RawSpan,
        tag: RawSpan,
        authenticatedData: RawSpan?
    ) throws {
        guard key.bitCount == ChaChaPoly.keyBitsCount else {
            throw CryptoKitError.incorrectKeySize
        }

        if let authenticatedData {
            try BoringSSLAEAD.chacha20.open(
                message: &message,
                key: key,
                nonce: nonce,
                tag: tag,
                authenticatedData: authenticatedData
            )
        } else {
            try BoringSSLAEAD.chacha20.open(
                message: &message,
                key: key,
                nonce: nonce,
                tag: tag,
                authenticatedData: RawSpan()
            )
        }

    }
}
#endif  // CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
