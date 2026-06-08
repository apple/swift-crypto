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
import CryptoBoringWrapper
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
enum OpenSSLAESGCMImpl {
    @inlinable
    static func seal<Plaintext: DataProtocol, AuthenticatedData: DataProtocol>(
        key: SymmetricKey,
        message: Plaintext,
        nonce: AES.GCM.Nonce?,
        authenticatedData: AuthenticatedData? = nil
    ) throws -> AES.GCM.SealedBox {
        let nonce = nonce ?? AES.GCM.Nonce()

        let aead = try Self._backingAEAD(key: key)

        let combined: Data
        if let ad = authenticatedData {
            combined = try aead.seal(
                message: message,
                key: key,
                nonce: nonce,
                authenticatedData: ad
            )
        } else {
            combined = try aead.seal(
                message: message,
                key: key,
                nonce: nonce,
                authenticatedData: []
            )
        }

        return AES.GCM.SealedBox(combined: combined, nonceByteCount: nonce.count)
    }

    #if swift(<6.3)
    @_lifetime(message: copy message)
    #endif
    @inlinable
    static func seal(
        key: SymmetricKey,
        message: inout MutableRawSpan,
        nonce: RawSpan,
        authenticatedData: RawSpan?,
        tag: inout OutputRawSpan
    ) throws {
        let aead = try Self._backingAEAD(key: key)

        if let ad = authenticatedData {
            try aead.seal(
                message: &message,
                key: key,
                nonce: nonce,
                authenticatedData: ad,
                tag: &tag
            )
        } else {
            try aead.seal(
                message: &message,
                key: key,
                nonce: nonce,
                authenticatedData: RawSpan(),
                tag: &tag
            )
        }
    }

    @inlinable
    static func open<AuthenticatedData: DataProtocol>(
        key: SymmetricKey,
        sealedBox: AES.GCM.SealedBox,
        authenticatedData: AuthenticatedData? = nil
    ) throws -> Data {
        let aead = try Self._backingAEAD(key: key)

        if let ad = authenticatedData {
            return try aead.open(
                ciphertext: sealedBox.ciphertext,
                key: key,
                nonce: sealedBox.nonce,
                tag: sealedBox.tag,
                authenticatedData: ad
            )
        } else {
            return try aead.open(
                ciphertext: sealedBox.ciphertext,
                key: key,
                nonce: sealedBox.nonce,
                tag: sealedBox.tag,
                authenticatedData: []
            )
        }
    }

    /// Open a given message in place.
    #if swift(<6.3)
    @_lifetime(message: copy message)
    #endif
    @inlinable
    static func open(
        key: SymmetricKey,
        message: inout MutableRawSpan,
        nonce: RawSpan,
        authenticatedData: RawSpan?,
        tag: RawSpan
    ) throws {
        let aead = try Self._backingAEAD(key: key)
        if let authenticatedData {
            return try aead.open(
                message: &message,
                key: key,
                nonce: nonce,
                tag: tag,
                authenticatedData: authenticatedData
            )
        } else {
            return try aead.open(
                message: &message,
                key: key,
                nonce: nonce,
                tag: tag,
                authenticatedData: RawSpan()
            )
        }
    }

    @usableFromInline
    static func _backingAEAD(key: SymmetricKey) throws -> BoringSSLAEAD {
        switch key.bitCount {
        case 128:
            return .aes128gcm
        case 192:
            return .aes192gcm
        case 256:
            return .aes256gcm
        default:
            throw CryptoKitError.incorrectKeySize
        }
    }
}
#endif  // CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
