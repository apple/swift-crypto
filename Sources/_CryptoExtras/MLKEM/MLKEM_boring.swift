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
@available(macOS 14.0, *)
public enum MLKEM {}

@available(macOS 14.0, *)
extension MLKEM {
    /// A ML-KEM-768 private key.
    public struct PrivateKey: Sendable, KEMPrivateKey {
        private var backing: Backing

        /// Initialize a ML-KEM-768 private key from a random seed.
        public init() {
            self.backing = Backing()
        }

        /// Generate a ML-KEM-768 private key from a random seed.
        ///
        /// - Returns: The generated private key.
        public static func generate() -> MLKEM.PrivateKey {
            .init()
        }

        /// Initialize a ML-KEM-768 private key from a seed.
        /// 
        /// - Parameter seed: The seed to use to generate the private key.
        /// 
        /// - Throws: `CryptoKitError.incorrectKeySize` if the seed is not 64 bytes long.
        public init(seed: some DataProtocol) throws {
            self.backing = try Backing(seed: seed)
        }

        /// The seed from which this private key was generated.
        public var seed: Data {
            self.backing.seed
        }

        /// The public key associated with this private key.
        public var publicKey: PublicKey {
            self.backing.publicKey
        }

        /// Decapsulate a shared secret and create a symmetric key.
        ///
        /// - Parameter encapsulated: The encapsulated shared secret.
        ///
        /// - Throws: `CryptoKitError.incorrectParameterSize` if the encapsulated shared secret is not 1088 bytes long.
        ///
        /// - Returns: The symmetric key.
        public func decapsulate(_ encapsulated: Data) throws -> SymmetricKey {
            try self.backing.decapsulate(encapsulated)
        }

        fileprivate final class Backing {
            var key: MLKEM768_private_key
            var seed: Data

            /// Initialize a ML-KEM-768 private key from a random seed.
            init() {
                self.key = .init()
                self.seed = Data()

                self.seed = withUnsafeTemporaryAllocation(of: UInt8.self, capacity: MLKEM.seedSizeInBytes) { seedPtr in
                    withUnsafeTemporaryAllocation(of: UInt8.self, capacity: MLKEM.PublicKey.bytesCount) { publicKeyPtr in
                        MLKEM768_generate_key(publicKeyPtr.baseAddress, seedPtr.baseAddress, &self.key)

                        return Data(bytes: seedPtr.baseAddress!, count: MLKEM.seedSizeInBytes)
                    }
                }
            }

            /// Initialize a ML-KEM-768 private key from a seed.
            /// 
            /// - Parameter seed: The seed to use to generate the private key.
            /// 
            /// - Throws: `CryptoKitError.incorrectKeySize` if the seed is not 64 bytes long.
            init(seed: some DataProtocol) throws {
                guard seed.count == MLKEM.seedSizeInBytes else {
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

            /// The public key associated with this private key.
            var publicKey: PublicKey {
                PublicKey(privateKeyBacking: self)
            }

            /// Decapsulate a shared secret and create a symmetric key.
            ///
            /// - Parameter encapsulated: The encapsulated shared secret.
            ///
            /// - Throws: `CryptoKitError.incorrectParameterSize` if the encapsulated shared secret is not 1088 bytes long.
            ///
            /// - Returns: The symmetric key.
            func decapsulate(_ encapsulated: Data) throws -> SymmetricKey {
                guard encapsulated.count == Int(MLKEM768_CIPHERTEXT_BYTES) else {
                    throw CryptoKitError.incorrectParameterSize
                }

                let output = try Array<UInt8>(unsafeUninitializedCapacity: Int(MLKEM_SHARED_SECRET_BYTES)) { bufferPtr, length in
                    let bytes: ContiguousBytes = encapsulated.regions.count == 1 ? encapsulated.regions.first! : Array(encapsulated)
                    let result = bytes.withUnsafeBytes { encapsulatedPtr in
                        MLKEM768_decap(
                            bufferPtr.baseAddress,
                            encapsulatedPtr.baseAddress,
                            encapsulatedPtr.count,
                            &self.key
                        )
                    }

                    guard result == 1 else {
                        throw CryptoKitError.internalBoringSSLError()
                    }

                    length = Int(MLKEM_SHARED_SECRET_BYTES)
                }

                return SymmetricKey(data: Data(output))
            }
        }
    }
}

@available(macOS 14.0, *)
extension MLKEM {
    /// A ML-KEM-768 public key.
    public struct PublicKey: Sendable, KEMPublicKey {
        private var backing: Backing

        fileprivate init(privateKeyBacking: PrivateKey.Backing) {
            self.backing = Backing(privateKeyBacking: privateKeyBacking)
        }

        /// Encapsulate a shared secret.
        ///
        /// - Returns: The shared secret and its encapsulated version.
        public func encapsulate() -> KEM.EncapsulationResult {
            self.backing.encapsulate()
        }

        /// The size of the public key in bytes.
        static let bytesCount = Backing.bytesCount

        fileprivate final class Backing {
            var key: MLKEM768_public_key

            init(privateKeyBacking: PrivateKey.Backing) {
                self.key = .init()
                MLKEM768_public_from_private(&self.key, &privateKeyBacking.key)
            }

            /// The size of the public key in bytes.
            static let bytesCount = Int(MLKEM768_PUBLIC_KEY_BYTES)
            
            /// Encapsulate a shared secret.
            ///
            /// - Returns: The shared secret and its encapsulated version.
            func encapsulate() -> KEM.EncapsulationResult {
                withUnsafeTemporaryAllocation(of: UInt8.self, capacity: Int(MLKEM768_CIPHERTEXT_BYTES)) { encapsulatedPtr in
                    withUnsafeTemporaryAllocation(of: UInt8.self, capacity: Int(MLKEM_SHARED_SECRET_BYTES)) { secretPtr in
                        MLKEM768_encap(
                            encapsulatedPtr.baseAddress,
                            secretPtr.baseAddress,
                            &self.key
                        )

                        return KEM.EncapsulationResult(
                            sharedSecret: SymmetricKey(data: Data(bytes: secretPtr.baseAddress!, count: Int(MLKEM_SHARED_SECRET_BYTES))),
                            encapsulated: Data(bytes: encapsulatedPtr.baseAddress!, count: Int(MLKEM768_CIPHERTEXT_BYTES))
                        )
                    }
                }
            }
        }
    }
}

@available(macOS 14.0, *)
extension MLKEM {
    /// The size of the seed in bytes.
    private static let seedSizeInBytes = Int(MLKEM_SEED_BYTES)
}