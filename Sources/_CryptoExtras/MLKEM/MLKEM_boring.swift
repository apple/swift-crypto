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

@_implementationOnly import CCryptoBoringSSL

/// A module-lattice-based key encapsulation mechanism that provides security against quantum computing attacks.
public enum MLKEM {}

extension MLKEM {
    /// A ML-KEM-768 private key.
    public struct PrivateKey: Sendable {
        private var backing: Backing

        /// Initialize a ML-KEM-768 private key from a random seed.
        public init() {
            self.backing = Backing()
        }

        /// Initialize a ML-KEM-768 private key from a seed.
        /// 
        /// - Parameter seed: The seed to use to generate the private key.
        /// 
        /// - Throws: `CryptoKitError.incorrectKeySize` if the seed is not 64 bytes long.
        public init(seed: some DataProtocol) throws {
            self.backing = try Backing(seed: seed)
        }

        fileprivate final class Backing {
            var key: MLKEM768_private_key
            var seed: Data

            /// Initialize a ML-KEM-768 private key from a random seed.
            init() {
                self.key = .init()
                self.seed = Data()

                self.seed = withUnsafeTemporaryAllocation(of: UInt8.self, capacity: Int(MLKEM_SEED_BYTES)) { seedPtr in
                    withUnsafeTemporaryAllocation(of: UInt8.self, capacity: Int(MLKEM768_PUBLIC_KEY_BYTES)) { publicKeyPtr in
                        MLKEM768_generate_key(publicKeyPtr.baseAddress, seedPtr.baseAddress, &self.key)

                        return Data(bytes: seedPtr.baseAddress!, count: Int(MLKEM_SEED_BYTES))
                    }
                }
            }

            /// Initialize a ML-KEM-768 private key from a seed.
            /// 
            /// - Parameter seed: The seed to use to generate the private key.
            /// 
            /// - Throws: `CryptoKitError.incorrectKeySize` if the seed is not 64 bytes long.
            init(seed: some DataProtocol) throws {
                guard seed.count == MLKEM_SEED_BYTES else {
                    throw CryptoKitError.incorrectKeySize
                }

                self.key = .init()
                self.seed = Data(seed)

                guard self.seed.withUnsafeBytes({ seedPtr in
                    MLKEM768_private_key_from_seed(
                        &self.key,
                        seedPtr.baseAddress,
                        seedPtr.count
                    )
                }) == 1 else {
                    throw CryptoKitError.internalBoringSSLError()
                }
            }
        }
    }
}