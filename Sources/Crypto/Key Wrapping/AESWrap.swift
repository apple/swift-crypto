//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2021 Apple Inc. and the SwiftCrypto project authors
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

#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
typealias AESWRAPImpl = CoreCryptoAESWRAPImpl
#else
typealias AESWRAPImpl = BoringSSLAESWRAPImpl
#endif

extension AES {
    /// The Key Wrapping module provides AES Key Wrapping, according to the IETF RFC 3394 specification.
    public enum KeyWrap {
        /// Wraps a key with AES wrap (RFC 3394), according to the IETF RFC 3394 specification.
        ///
        /// - Parameters:
        ///   - keyToWrap: The key to wrap
        ///   - kek: The Key Encryption Key
        /// - Returns: The wrapped key
        public static func wrap(_ keyToWrap: SymmetricKey, using kek: SymmetricKey) throws -> Data {
            return try AESWRAPImpl.wrap(key: kek, keyToWrap: keyToWrap)
        }

        /// Unwraps a key with AES wrap, according to the IETF RFC 3394 specification.
        ///
        /// - Parameters:
        ///   - wrappedKey: The wrapped key
        ///   - kek: The key encryption key
        /// - Returns: The unwrapped key, the method will throw if the payload was incorrectly wrapped.
        public static func unwrap<WrappedKey: DataProtocol>(_ wrappedKey: WrappedKey, using kek: SymmetricKey) throws -> SymmetricKey {
            return try AESWRAPImpl.unwrap(key: kek, wrappedKey: wrappedKey)
        }
    }
}

#endif // Linux or !SwiftPM
