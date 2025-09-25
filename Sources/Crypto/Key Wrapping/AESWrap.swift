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

#if (!CRYPTO_IN_SWIFTPM_FORCE_BUILD_API) || CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias AESWRAPImpl = CoreCryptoAESWRAPImpl
#else
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias AESWRAPImpl = BoringSSLAESWRAPImpl
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AES {
    /// An implementation of AES Key Wrapping in accordance with the IETF RFC
    /// 3394 specification.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum KeyWrap: Sendable {
        /// Wraps a key using the AES wrap algorithm.
        ///
        /// Wrap is an implementation of the AES key wrap algorithm as specified
        /// in IETF RFC 3394.
        ///
        /// - Parameters:
        ///   - keyToWrap: The key to wrap.
        ///   - kek: The key encryption key.
        ///
        /// - Returns: The wrapped key.
        public static func wrap(_ keyToWrap: SymmetricKey, using kek: SymmetricKey) throws -> Data {
            return try AESWRAPImpl.wrap(key: kek, keyToWrap: keyToWrap)
        }

        /// Unwraps a key using the AES wrap algorithm.
        ///
        /// Wrap is an implementation of the AES key wrap algorithm as specified
        /// in IETF RFC 3394. The method throws an error is the key was
        /// incorrectly wrapped.
        ///
        /// - Parameters:
        ///   - wrappedKey: The key to unwrap.
        ///   - kek: The key encryption key.
        ///
        /// - Returns: The unwrapped key.
        public static func unwrap<WrappedKey: DataProtocol>(_ wrappedKey: WrappedKey, using kek: SymmetricKey) throws -> SymmetricKey {
            return try AESWRAPImpl.unwrap(key: kek, wrappedKey: wrappedKey)
        }
    }
}

#endif // Linux or !SwiftPM
