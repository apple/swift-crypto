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

protocol MACAlgorithm {
    associatedtype Key
    #if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
    associatedtype MAC: CryptoKit.MessageAuthenticationCode
    #else
    associatedtype MAC: Crypto.MessageAuthenticationCode
    #endif

    /// Initializes the MAC Algorithm
    ///
    /// - Parameter key: The key used to authenticate the data
    init(key: Key)

    /// Updates the MAC with the buffer.
    ///
    /// - Parameter bufferPointer: The buffer to update the MAC
    mutating func update(bufferPointer: UnsafeRawBufferPointer)

    /// Returns the MAC from the input in the MAC Algorithm instance.
    ///
    /// - Returns: The Message Authentication Code
    func finalize() -> MAC
}

extension MACAlgorithm {
    /// Computes a Message Authentication Code.
    ///
    /// - Parameters:
    ///   - bufferPointer: The buffer to authenticate
    ///   - key: The key used to authenticate the data
    /// - Returns: A Message Authentication Code
    static func authenticationCode(bufferPointer: UnsafeRawBufferPointer, using key: Key) -> MAC {
        // swiftlint:disable:next explicit_init
        var authenticator = Self(key: key)
        // swiftlint:disable:previous explicit_init
        authenticator.update(bufferPointer: bufferPointer)
        return authenticator.finalize()
    }
    
    /// Verifies a Message Authentication Code. The comparison is done in constant-time.
    ///
    /// - Parameters:
    ///   - key: The key used to authenticate the data
    ///   - bufferPointer: The buffer to authenticate
    ///   - mac: The MAC to verify
    /// - Returns: Returns true if the MAC is valid. False otherwise.
    static func isValidAuthenticationCode(_ mac: MAC, authenticating bufferPointer: UnsafeRawBufferPointer, using key: Key) -> Bool {
        return mac == Self.authenticationCode(bufferPointer: bufferPointer, using: key)
    }
}
#endif // Linux or !SwiftPM
