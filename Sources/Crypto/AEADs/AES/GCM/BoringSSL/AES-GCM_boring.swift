//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
@_implementationOnly import CCryptoBoringSSL
import Foundation

enum OpenSSLAESGCMImpl {
    @inlinable
    static func seal<Plaintext: DataProtocol, AuthenticatedData: DataProtocol>
    (key: SymmetricKey, message: Plaintext, nonce: AES.GCM.Nonce?, authenticatedData: AuthenticatedData? = nil) throws -> AES.GCM.SealedBox {
        let nonce = nonce ?? AES.GCM.Nonce()

        let aead = try Self._backingAEAD(key: key)

        let ciphertext: Data
        let tag: Data
        if let ad = authenticatedData {
            (ciphertext, tag) = try aead.seal(message: message, key: key, nonce: nonce, authenticatedData: ad)
        } else {
            (ciphertext, tag) = try aead.seal(message: message, key: key, nonce: nonce, authenticatedData: [])
        }

        return try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
    }

    @inlinable
    static func open<AuthenticatedData: DataProtocol>
    (key: SymmetricKey, sealedBox: AES.GCM.SealedBox, authenticatedData: AuthenticatedData? = nil) throws -> Data {
        let aead = try Self._backingAEAD(key: key)

        if let ad = authenticatedData {
            return try aead.open(ciphertext: sealedBox.ciphertext, key: key, nonce: sealedBox.nonce, tag: sealedBox.tag, authenticatedData: ad)
        } else {
            return try aead.open(ciphertext: sealedBox.ciphertext, key: key, nonce: sealedBox.nonce, tag: sealedBox.tag, authenticatedData: [])
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
#endif // (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
