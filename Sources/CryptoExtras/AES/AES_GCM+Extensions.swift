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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AES.GCM {
    /// Secures the given plaintext message with encryption and an authentication tag.
    ///
    /// - Parameters:
    ///   - message: The plaintext data to seal.
    ///   - key: A cryptographic key used to seal the message.
    ///   - nonce: The nonce the sealing process requires.
    ///   - authenticatedData: Additional data to be authenticated, if provided.
    ///   - tag: Receives the 16-byte authentication tag. Needs at least 16 bytes of free capacity.
    ///   - output: Receives the encrypted message. Needs at least `message.byteCount` bytes of free capacity.
    ///
    /// The call traps if `tag` or `output` lacks the free capacity. If the call throws, `tag` and
    /// `output` are unchanged.
    #if compiler(<6.3)
    @_lifetime(tag: copy tag)
    @_lifetime(output: copy output)
    #endif
    public static func _seal(
        _ message: RawSpan,
        using key: SymmetricKey,
        nonce: Nonce,
        authenticating authenticatedData: RawSpan? = nil,
        tag: inout OutputRawSpan,
        output: inout OutputRawSpan
    ) throws(CryptoKitMetaError) {
        try OpenSSLAESGCMImpl.seal(
            key: key,
            message: message,
            output: &output,
            nonce: nonce,
            authenticatedData: authenticatedData,
            tag: &tag
        )
    }

    /// Decrypts the message and verifies its authenticity.
    ///
    /// - Parameters:
    ///   - message: The ciphertext to decrypt.
    ///   - key: The cryptographic key that was used to seal the message.
    ///   - nonce: The nonce used to encrypt the message.
    ///   - authenticatedData: Additional data that was authenticated, if provided.
    ///   - tag: The 16-byte authentication tag.
    ///   - output: Receives the decrypted message. Needs at least `message.byteCount` bytes of free capacity.
    ///
    /// The call traps if `output` lacks the free capacity. The call throws an error if decryption or
    /// authentication fail, and leaves `output` unchanged.
    #if compiler(<6.3)
    @_lifetime(output: copy output)
    #endif
    public static func _open(
        _ message: RawSpan,
        using key: SymmetricKey,
        nonce: Nonce,
        authenticating authenticatedData: RawSpan? = nil,
        tag: RawSpan,
        output: inout OutputRawSpan
    ) throws(CryptoKitMetaError) {
        try OpenSSLAESGCMImpl.open(
            key: key,
            message: message,
            output: &output,
            nonce: nonce,
            authenticatedData: authenticatedData,
            tag: tag
        )
    }
}
