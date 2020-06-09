//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
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
import Foundation

protocol AEADSealedBox {
    associatedtype Nonce: Sequence
    /// The authentication tag
    var tag: Data { get }
    /// The ciphertext
    var ciphertext: Data { get }
    /// The Nonce
    var nonce: Nonce { get }

    /// Initializes a SealedBox from a tag and ciphertext data. May fail if the authentication tag is not expected size.
    ///
    /// - Parameters:
    ///   - nonce: The nonce.
    ///   - tag: The authentication tag
    ///   - ciphertext: The ciphertext
    init<C: DataProtocol, T: DataProtocol>(nonce: Nonce, ciphertext: C, tag: T) throws
}

/// A type representing authenticated encryption with associated data.
protocol Cipher {
    associatedtype Key
    associatedtype SealedBox: AEADSealedBox
    associatedtype Nonce: Sequence

    /// Seals the box. This encrypts and authenticates the message. Optionally, additional data can also be authenticated.
    ///
    /// - Parameters:
    ///   - key: The key used to seal.
    ///   - message: The message to seal.
    ///   - nonce: A Nonce used for sealing.
    ///   - authenticatedData: Optional additional data to be authenticated.
    /// - Returns: The sealed box containing the ciphertext and authentication tag
    /// - Throws: An error occurred while encrypting or authenticating.
    static func seal<Plaintext: DataProtocol, AuthenticatedData: DataProtocol>
        (_ message: Plaintext, using key: SymmetricKey, nonce: Nonce?, authenticating: AuthenticatedData) throws -> SealedBox

    /// Opens the sealed box. This decrypts and verifies the authenticity of the message,
    /// and optionally verifies the authenticity of the authenticated data.
    ///
    /// - Parameters:
    ///   - key: The key used to seal.
    ///   - sealedBox: The sealed box to open
    ///   - nonce: The nonce used for sealing
    ///   - authenticatedData: The data that was authenticated.
    /// - Returns: Returns the data, if the correct key is used and the authenticated data matches the one from the seal operation.
    /// - Throws: An error occurred while decrypting or authenticating.
    static func open<AuthenticatedData: DataProtocol>
        (_ sealedBox: SealedBox, using key: Key, authenticating: AuthenticatedData) throws -> Data
}
#endif
