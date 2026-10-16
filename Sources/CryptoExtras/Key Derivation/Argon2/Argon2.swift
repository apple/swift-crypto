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
import Foundation

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension KDF {
    /// An implementation of the Argon2id key derivation function as defined in RFC 9106.
    public enum Argon2id: Sendable {
        /// Derives a symmetric key using the Argon2id algorithm.
        ///
        /// - Parameters:
        ///    - password: The passphrase used as a basis for the key.
        ///    - salt: The salt to use for key derivation (recommended at least 16 bytes).
        ///    - outputByteCount: The length in bytes of the resulting symmetric key.
        ///    - iterations: The number of passes over memory (time cost).
        ///    - memoryByteCount: The memory cost in bytes.
        ///    - parallelism: The number of independent lanes.
        ///    - secret: Optional secret data (key) to be hashed.
        ///    - associatedData: Optional additional associated data to be hashed.
        /// - Returns: The derived symmetric key.
        public static func deriveKey<Passphrase: DataProtocol, Salt: DataProtocol>(
            from password: Passphrase,
            salt: Salt,
            outputByteCount: Int,
            iterations: Int,
            memoryByteCount: Int,
            parallelism: Int,
            secret: Data? = nil,
            associatedData: Data? = nil
        ) throws -> SymmetricKey {
            let hash = try Argon2NativeImplementation.hash(
                password: password,
                salt: salt,
                iterations: iterations,
                memoryBytes: memoryByteCount,
                parallelism: parallelism,
                outputLength: outputByteCount,
                variant: .id,
                secret: secret,
                associatedData: associatedData
            )
            return SymmetricKey(data: hash)
        }
    }
}
