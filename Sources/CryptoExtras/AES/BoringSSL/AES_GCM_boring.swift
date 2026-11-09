//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import CryptoBoringWrapper

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLAEAD {
    /// Seal a given message with caller owned buffers.
    #if compiler(<6.3)
    @_lifetime(tag: copy tag)
    @_lifetime(output: copy output)
    #endif
    func seal(
        message: RawSpan,
        key: SymmetricKey,
        output: inout OutputRawSpan,
        nonce: RawSpan,
        authenticatedData: RawSpan,
        tag: inout OutputRawSpan
    ) throws {
        do {
            let context = try AEADContext(cipher: self, key: key)
            return try context.seal(
                message: message,
                output: &output,
                nonce: nonce,
                authenticatedData: authenticatedData,
                tag: &tag
            )
        } catch CryptoBoringWrapperError.underlyingCoreCryptoError(let errorCode) {
            throw CryptoKitError.underlyingCoreCryptoError(error: errorCode)
        }
    }

    /// Open a given message with caller owned buffers.
    #if compiler(<6.3)
    @_lifetime(output: copy output)
    #endif
    func open(
        message: RawSpan,
        key: SymmetricKey,
        output: inout OutputRawSpan,
        nonce: RawSpan,
        tag: RawSpan,
        authenticatedData: RawSpan
    ) throws {
        do {
            let context = try AEADContext(cipher: self, key: key)
            return try context.open(
                message: message,
                output: &output,
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
enum OpenSSLAESGCMImpl {
    #if compiler(<6.3)
    @_lifetime(tag: copy tag)
    @_lifetime(output: copy output)
    #endif
    static func seal(
        key: SymmetricKey,
        message: RawSpan,
        output: inout OutputRawSpan,
        nonce: AES.GCM.Nonce,
        authenticatedData: RawSpan?,
        tag: inout OutputRawSpan
    ) throws {
        let aead = try Self._backingAEAD(key: key)
        let authenticatedData = if let authenticatedData { authenticatedData } else { RawSpan() }
        try nonce.withUnsafeBytes { nonceBuffer in
            try aead.seal(
                message: message,
                key: key,
                output: &output,
                nonce: nonceBuffer.bytes,
                authenticatedData: authenticatedData,
                tag: &tag
            )
        }
    }

    #if compiler(<6.3)
    @_lifetime(output: copy output)
    #endif
    static func open(
        key: SymmetricKey,
        message: RawSpan,
        output: inout OutputRawSpan,
        nonce: AES.GCM.Nonce,
        authenticatedData: RawSpan?,
        tag: RawSpan
    ) throws {
        let aead = try Self._backingAEAD(key: key)
        let authenticatedData = if let authenticatedData { authenticatedData } else { RawSpan() }
        try nonce.withUnsafeBytes { nonceBuffer in
            try aead.open(
                message: message,
                key: key,
                output: &output,
                nonce: nonceBuffer.bytes,
                tag: tag,
                authenticatedData: authenticatedData
            )
        }
    }

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
