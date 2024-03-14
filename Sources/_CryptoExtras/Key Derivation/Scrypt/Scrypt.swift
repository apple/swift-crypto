//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import Crypto
#if canImport(Darwin) || swift(>=5.9.1)
import Foundation
#else
@preconcurrency import Foundation
#endif

fileprivate typealias BackingScrypt = BoringSSLScrypt

extension KDF {
    /// An implementation of scrypt key derivation function.
    public struct Scrypt {
        /// Derives a symmetric key using the scrypt algorithm.
        ///
        /// - Parameters:
        ///    - password: The passphrase, which should be used as a basis for the key. This can be any type that conforms to `DataProtocol`, like `Data` or an array of `UInt8` instances.
        ///    - salt: The salt to use for key derivation.
        ///    - outputByteCount: The length in bytes of resulting symmetric key.
        ///    - rounds: The number of rounds which should be used to perform key derivation. Must be a power of 2 less than `2^(128 * blockSize / 8)`.
        ///    - blockSize: The block size to use for key derivation.
        ///    - parallelism: The parallelism factor to use for key derivation. Must be a positive integer less than or equal to `((2^32 - 1) * 32) / (128 * blockSize)`.
        /// - Returns: The derived symmetric key.
        public static func deriveKey<Passphrase: DataProtocol, Salt: DataProtocol>(from password: Passphrase, salt: Salt, outputByteCount: Int, rounds: Int = 16_384, blockSize: Int = 8, parallelism: Int = 1) throws -> SymmetricKey {
            return try BackingScrypt.deriveKey(from: password, salt: salt, outputByteCount: outputByteCount, rounds: rounds, blockSize: blockSize, parallelism: parallelism)
        }
    }
}
