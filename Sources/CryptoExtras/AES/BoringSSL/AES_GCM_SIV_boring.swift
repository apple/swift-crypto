//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// This is a copy ChaChaPoly_boring just with a different set aes algos

@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims
import Crypto
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
            return try context.seal(message: message, nonce: nonce, authenticatedData: authenticatedData)
        } catch CryptoBoringWrapperError.underlyingCoreCryptoError(let errorCode) {
            throw CryptoKitError.underlyingCoreCryptoError(error: errorCode)
        }
    }

    /// Open a given message.
    func open<Nonce: ContiguousBytes, AuthenticatedData: DataProtocol>(
        combinedCiphertextAndTag: Data,
        key: SymmetricKey,
        nonce: Nonce,
        authenticatedData: AuthenticatedData
    ) throws -> Data {
        do {
            let context = try AEADContext(cipher: self, key: key)
            return try context.open(
                combinedCiphertextAndTag: combinedCiphertextAndTag,
                nonce: nonce,
                authenticatedData: authenticatedData
            )
        } catch CryptoBoringWrapperError.underlyingCoreCryptoError(let errorCode) {
            throw CryptoKitError.underlyingCoreCryptoError(error: errorCode)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
enum OpenSSLAESGCMSIVImpl {
    @inlinable
    static func seal<Plaintext: DataProtocol, AuthenticatedData: DataProtocol>(
        key: SymmetricKey,
        message: Plaintext,
        nonce: AES.GCM._SIV.Nonce?,
        authenticatedData: AuthenticatedData? = nil
    ) throws -> AES.GCM._SIV.SealedBox {
        let nonce = nonce ?? AES.GCM._SIV.Nonce()

        let aead = try Self._backingAEAD(key: key)

        let ciphertext: Data
        let tag: Data
        if let ad = authenticatedData {
            (ciphertext, tag) = try aead.seal(
                message: message,
                key: key,
                nonce: nonce,
                authenticatedData: ad
            )
        } else {
            (ciphertext, tag) = try aead.seal(
                message: message,
                key: key,
                nonce: nonce,
                authenticatedData: []
            )
        }

        return try AES.GCM._SIV.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
    }

    @inlinable
    static func open<AuthenticatedData: DataProtocol>(
        key: SymmetricKey,
        sealedBox: AES.GCM._SIV.SealedBox,
        authenticatedData: AuthenticatedData? = nil
    ) throws -> Data {
        let aead = try Self._backingAEAD(key: key)

        if let ad = authenticatedData {
            return try aead.open(
                combinedCiphertextAndTag: sealedBox.combined.dropFirst(AES.GCM._SIV.nonceByteCount),
                key: key,
                nonce: sealedBox.nonce,
                authenticatedData: ad
            )
        } else {
            return try aead.open(
                combinedCiphertextAndTag: sealedBox.combined.dropFirst(AES.GCM._SIV.nonceByteCount),
                key: key,
                nonce: sealedBox.nonce,
                authenticatedData: []
            )
        }
    }

    @usableFromInline
    static func _backingAEAD(key: SymmetricKey) throws -> BoringSSLAEAD {
        switch key.bitCount {
        case 128:
            return .aes128gcmsiv
        case 256:
            return .aes256gcmsiv
        default:
            throw CryptoKitError.incorrectKeySize
        }
    }
}
