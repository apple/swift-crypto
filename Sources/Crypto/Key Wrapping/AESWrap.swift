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

#if canImport(CryptoKit)
@_exported import CryptoKit
#else

#if canImport(FoundationEssentials)
public import FoundationEssentials
#else
public import Foundation
#endif

typealias AESWRAPImpl = BoringSSLAESWRAPImpl

extension AES {
    /// An implementation of AES Key Wrapping in accordance with the IETF RFC
    /// 3394 specification.
    @nonexhaustive
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

#endif // canImport(CryptoKit)
