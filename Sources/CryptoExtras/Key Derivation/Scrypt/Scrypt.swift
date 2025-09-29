//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import Crypto
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
fileprivate typealias BackingScrypt = BoringSSLScrypt

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension KDF {
    /// An implementation of scrypt key derivation function.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum Scrypt: Sendable {
        /// Derives a symmetric key using the scrypt algorithm.
        ///
        /// - Parameters:
        ///    - password: The passphrase, which should be used as a basis for the key. This can be any type that conforms to `DataProtocol`, like `Data` or an array of `UInt8` instances.
        ///    - salt: The salt to use for key derivation.
        ///    - outputByteCount: The length in bytes of resulting symmetric key.
        ///    - rounds: The number of rounds which should be used to perform key derivation. Must be a power of 2 less than `2^(128 * blockSize / 8)`.
        ///    - blockSize: The block size to use for key derivation.
        ///    - parallelism: The parallelism factor to use for key derivation. Must be a positive integer less than or equal to `((2^32 - 1) * 32) / (128 * blockSize)`.
        ///    - maxMemory: The maximum amount of memory allowed to use for key derivation. If not provided, the default value is computed for the provided parameters.
        /// - Returns: The derived symmetric key.
        public static func deriveKey<Passphrase: DataProtocol, Salt: DataProtocol>(from password: Passphrase, salt: Salt, outputByteCount: Int, rounds: Int, blockSize: Int, parallelism: Int, maxMemory: Int? = nil) throws -> SymmetricKey {
            return try BackingScrypt.deriveKey(from: password, salt: salt, outputByteCount: outputByteCount, rounds: rounds, blockSize: blockSize, parallelism: parallelism)
        }
    }
}
