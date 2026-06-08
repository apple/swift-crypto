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
#if (!CRYPTO_IN_SWIFTPM_FORCE_BUILD_API) || CRYPTOKIT_NO_ACCESS_TO_FOUNDATION || CRYPTOKIT_NO_IMPORT_FOUNDATION
#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.13, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, visionOS 1.0, *)
#endif
typealias ChaChaPolyImpl = CoreCryptoChaChaPolyImpl
#else
typealias ChaChaPolyImpl = OpenSSLChaChaPolyImpl
#endif

#if CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
public import SwiftSystem
#elseif CRYPTOKIT_NO_IMPORT_FOUNDATION
#else
#if canImport(FoundationEssentials)
public import FoundationEssentials
#else
public import Foundation
#endif
#endif


/// An implementation of the ChaCha20-Poly1305 cipher.
#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.13, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, visionOS 1.0, *)
#endif
public enum ChaChaPoly: Cipher, Sendable {
    static let tagByteCount = 16
    static let keyBitsCount = 256
    static let nonceByteCount = 12

    /// Secures the given plaintext message with encryption and an
    /// authentication tag that covers both the encrypted data and additional
    /// data.
    ///
    /// - Parameters:
    ///   - message: The plaintext data to seal.
    ///   - key: A cryptographic key used to seal the message.
    ///   - nonce: The nonce the sealing process requires. If you don't provide a nonce, the method generates a random one by invoking ``ChaChaPoly/Nonce/init()``.
    ///   - authenticatedData: Additional data to be authenticated.
    ///
    /// - Returns: The sealed message.
    public static func seal<Plaintext: DataProtocol, AuthenticatedData: DataProtocol>
        (_ message: Plaintext, using key: SymmetricKey, nonce: Nonce? = nil, authenticating authenticatedData: AuthenticatedData) throws -> SealedBox {
        return try ChaChaPolyImpl.encrypt(key: key, message: message, nonce: nonce, authenticatedData: authenticatedData)
    }

    /// Secures the given plaintext message with encryption and an
    /// authentication tag.
    ///
    /// - Parameters:
    ///   - message: The plaintext data to seal.
    ///   - key: A cryptographic key used to seal the message.
    ///   - nonce: The nonce the sealing process requires. If you don't provide a nonce, the method generates a random one by invoking ``ChaChaPoly/Nonce/init()``.
    ///
    /// - Returns: The sealed message.
    public static func seal<Plaintext: DataProtocol>
        (_ message: Plaintext, using key: SymmetricKey, nonce: Nonce? = nil) throws -> SealedBox {
        return try ChaChaPolyImpl.encrypt(key: key, message: message, nonce: nonce, authenticatedData: Data?.none)
    }

    /// Secures the given plaintext message in place with encryption and an
    /// authentication tag.
    ///
    /// - Parameters:
    ///   - message: The plaintext data to seal.
    ///   - key: A cryptographic key used to seal the message.
    ///   - nonce: The nonce the sealing process requires.
    ///   - authenticatedData: Additional data to be authenticated.
    ///   - tag: Will be updated with the 16-byte authentication tag.
    @available(iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0, macCatalyst 27.0, visionOS 27.0, *)
    #if swift(<6.3)
    @_lifetime(message: copy message)
    #endif
    public static func seal(
        inPlace message: inout MutableRawSpan,
        using key: SymmetricKey,
        nonce: Nonce,
        authenticating authenticatedData: RawSpan? = nil,
        tag: inout OutputRawSpan
    ) throws(CryptoKitMetaError) {
        try ChaChaPolyImpl.encrypt(key: key, inPlace: &message, nonce: nonce.bytes, authenticatedData: authenticatedData, tag: &tag)
    }

    // Note: historical version of the above, which should be removed once
    // the above is API and clients move over to it.
    #if swift(<6.3)
    @_lifetime(message: copy message)
    #endif
    internal static func seal(
        inplace message: inout MutableRawSpan,
        using key: SymmetricKey,
        nonce: RawSpan,
        authenticating authenticatedData: RawSpan? = nil,
        tag: inout OutputRawSpan
    ) throws(CryptoKitMetaError) {
        try ChaChaPolyImpl.encrypt(key: key, inPlace: &message, nonce: nonce, authenticatedData: authenticatedData, tag: &tag)
    }

    /// Decrypts the message and verifies the authenticity of both the encrypted
    /// message and additional data.
    ///
    /// - Parameters:
    ///   - sealedBox: The sealed box to open.
    ///   - key: The cryptographic key that was used to seal the message.
    ///   - authenticatedData: Additional data that was authenticated.
    ///
    /// - Returns: The original plaintext message that was sealed in the box, as
    /// long as the correct key is used and authentication succeeds. The call
    /// throws an error if decryption or authentication fail.
    public static func open<AuthenticatedData: DataProtocol>
        (_ sealedBox: SealedBox, using key: SymmetricKey, authenticating authenticatedData: AuthenticatedData) throws -> Data {
        return try ChaChaPolyImpl.decrypt(key: key, ciphertext: sealedBox, authenticatedData: authenticatedData)
    }

    /// Decrypts the message and verifies its authenticity.
    ///
    /// - Parameters:
    ///   - sealedBox: The sealed box to open.
    ///   - key: The cryptographic key that was used to seal the message.
    ///
    /// - Returns: The original plaintext message that was sealed in the box, as
    /// long as the correct key is used and authentication succeeds. The call
    /// throws an error if decryption or authentication fail.
    public static func open
        (_ sealedBox: SealedBox, using key: SymmetricKey) throws -> Data {
        return try ChaChaPolyImpl.decrypt(key: key, ciphertext: sealedBox, authenticatedData: Data?.none)
    }

    /// Decrypts the message and verifies the authenticity of both the encrypted
    /// message and additional data.
    ///
    /// - Parameters:
    ///   - message: The message, which will be decrypted in place.
    ///   - key: The cryptographic key that was used to seal the message.
    ///   - nonce: The nonce used to encrypt the message.
    ///   - tag : The 16-byte authentication tag.
    ///   - authenticatedData: Additional data that was authenticated.
    ///
    /// The call throws an error if decryption or authentication fail.
    @available(iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0, macCatalyst 27.0, visionOS 27.0, *)
    #if swift(<6.3)
    @_lifetime(message: copy message)
    #endif
    public static func open(
        inPlace message: inout MutableRawSpan,
        using key: SymmetricKey,
        nonce: Nonce,
        authenticating authenticatedData: RawSpan? = nil,
        tag: RawSpan
    ) throws(CryptoKitMetaError) {
        try ChaChaPolyImpl.decrypt(key: key, inPlace: &message, nonce: nonce.bytes, tag: tag, authenticatedData: authenticatedData)
    }

    // Note: historical version of the above, which should be removed once
    // the above is API and clients move over to it.
    #if swift(<6.3)
    @_lifetime(message: copy message)
    #endif
    public static func open(
        inplace message: inout MutableRawSpan,
        using key: SymmetricKey,
        nonce: RawSpan,
        tag: RawSpan,
        authenticating authenticatedData: RawSpan? = nil
    ) throws(CryptoKitMetaError) {
        try ChaChaPolyImpl.decrypt(key: key, inPlace: &message, nonce: nonce, tag: tag, authenticatedData: authenticatedData)
    }
}

#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.13, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, visionOS 1.0, *)
#endif
extension ChaChaPoly {
    /// A secure container for your data that you access using a cipher.
    ///
    /// Use a sealed box as a container for data that you want to transmit
    /// securely. Seal data into a box with one of the cipher algorithms, like
    /// ``seal(_:using:nonce:)``.
    ///
    /// The box holds an encrypted version of the original data, an
    /// authentication tag, and the nonce during encryption. The encryption
    /// makes the data unintelligible to anyone without the key, while the
    /// authentication tag makes it possible for the intended receiver to be
    /// sure the data remains intact.
    ///
    /// The receiver uses another instance of the same cipher, like the
    /// ``open(_:using:)`` method, to open the box.
    @frozen
    #if !CRYPTOKIT_STATIC_LIBRARY
    @available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
    #else // CRYPTOKIT_STATIC_LIBRARY
    @available(iOS 13.0, macOS 10.13, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, visionOS 1.0, *)
    #endif
    public struct SealedBox: AEADSealedBox, Sendable {
        /// A combined element composed of the tag, the nonce, and the
        /// ciphertext.
        ///
        /// The data layout of the combined representation is: nonce,
        /// ciphertext, then tag.
        public let combined: Data
        /// An authentication tag.
        ///
        /// The authentication tag has a length of 16 bytes.
        public var tag: Data {
            return combined.suffix(ChaChaPoly.tagByteCount)
        }
        /// The encrypted data.
        public var ciphertext: Data {
            return combined.dropFirst(ChaChaPoly.nonceByteCount).dropLast(ChaChaPoly.tagByteCount)
        }
        /// The nonce used to encrypt the data.
        public var nonce: ChaChaPoly.Nonce {
            return try! ChaChaPoly.Nonce(data: combined.prefix(ChaChaPoly.nonceByteCount))
        }
        
        /// Creates a sealed box from the given data.
        ///
        /// - Parameters:
        ///   - combined: The combined bytes of the tag and ciphertext.
        @inlinable
        public init<D: DataProtocol>(combined: D) throws {
            // ChachaPoly nonce (12 bytes) + ChachaPoly tag (16 bytes)
            // While we have these values in the internal APIs, we can't use it in inlinable code.
            let chachaPolyOverhead = 12 + 16
            
            if combined.count < chachaPolyOverhead {
                throw CryptoKitError.incorrectParameterSize
            }
            
            self.combined = Data(combined)
        }
        
        /// Creates a sealed box from the given tag, nonce, and ciphertext.
        ///
        /// - Parameters:
        ///   - nonce: The nonce.
        ///   - ciphertext: The encrypted data.
        ///   - tag: An authentication tag.
        public init<C: DataProtocol, T: DataProtocol>(nonce: ChaChaPoly.Nonce, ciphertext: C, tag: T) throws {
            guard tag.count == ChaChaPoly.tagByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }
            
            self.combined = Data(nonce) + ciphertext + tag
        }

        internal init(combined: Data, nonceByteCount: Int) {
            assert(nonceByteCount == ChaChaPoly.nonceByteCount)
            self.combined = combined
        }
    }
}
#endif // Linux or !SwiftPM
