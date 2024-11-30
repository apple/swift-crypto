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

@_implementationOnly import CCryptoBoringSSL
import Crypto
import Foundation

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
                    withUnsafeTemporaryAllocation(
                        of: UInt8.self, capacity: MLKEM.PublicKey.bytesCount
                    ) { publicKeyPtr in
                        CCryptoBoringSSL_MLKEM768_generate_key(publicKeyPtr.baseAddress, seedPtr.baseAddress, &self.key)

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

                guard
                    self.seed.withUnsafeBytes({ seedPtr in
                        CCryptoBoringSSL_MLKEM768_private_key_from_seed(
                            &self.key,
                            seedPtr.baseAddress,
                            seedPtr.count
                        )
                    }) == 1
                else {
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
                guard encapsulated.count == MLKEM.ciphertextSizeInBytes else {
                    throw CryptoKitError.incorrectParameterSize
                }

                let output = try [UInt8](
                    unsafeUninitializedCapacity: MLKEM.sharedSecretSizeInBytes
                ) { bufferPtr, length in
                    let bytes: ContiguousBytes =
                        encapsulated.regions.count == 1
                        ? encapsulated.regions.first!
                        : Array(encapsulated)
                    let result = bytes.withUnsafeBytes { encapsulatedPtr in
                        CCryptoBoringSSL_MLKEM768_decap(
                            bufferPtr.baseAddress,
                            encapsulatedPtr.baseAddress,
                            encapsulatedPtr.count,
                            &self.key
                        )
                    }

                    guard result == 1 else {
                        throw CryptoKitError.internalBoringSSLError()
                    }

                    length = MLKEM.sharedSecretSizeInBytes
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

        /// Initialize a ML-KEM-768 public key from a raw representation.
        ///
        /// - Parameter rawRepresentation: The public key bytes.
        ///
        /// - Throws: `CryptoKitError.incorrectKeySize` if the raw representation is not the correct size.
        init(rawRepresentation: some DataProtocol) throws {
            self.backing = try Backing(rawRepresentation: rawRepresentation)
        }

        /// The raw binary representation of the public key.
        public var rawRepresentation: Data {
            self.backing.rawRepresentation
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
                CCryptoBoringSSL_MLKEM768_public_from_private(&self.key, &privateKeyBacking.key)
            }

            /// Initialize a ML-KEM-768 public key from a raw representation.
            ///
            /// - Parameter rawRepresentation: The public key bytes.
            ///
            /// - Throws: `CryptoKitError.incorrectKeySize` if the raw representation is not the correct size.
            init(rawRepresentation: some DataProtocol) throws {
                guard rawRepresentation.count == MLKEM.PublicKey.bytesCount else {
                    throw CryptoKitError.incorrectKeySize
                }

                self.key = .init()

                let bytes: ContiguousBytes =
                    rawRepresentation.regions.count == 1
                    ? rawRepresentation.regions.first!
                    : Array(rawRepresentation)
                try bytes.withUnsafeBytes { rawBuffer in
                    try rawBuffer.withMemoryRebound(to: UInt8.self) { buffer in
                        var cbs = CBS(data: buffer.baseAddress, len: buffer.count)
                        guard CCryptoBoringSSL_MLKEM768_parse_public_key(&self.key, &cbs) == 1 else {
                            throw CryptoKitError.internalBoringSSLError()
                        }
                    }
                }
            }

            /// The raw binary representation of the public key.
            var rawRepresentation: Data {
                var cbb = CBB()
                // The following BoringSSL functions can only fail on allocation failure, which we define as impossible.
                CCryptoBoringSSL_CBB_init(&cbb, MLKEM.PublicKey.Backing.bytesCount)
                defer { CCryptoBoringSSL_CBB_cleanup(&cbb) }
                CCryptoBoringSSL_MLKEM768_marshal_public_key(&cbb, &self.key)
                return Data(bytes: CCryptoBoringSSL_CBB_data(&cbb), count: CCryptoBoringSSL_CBB_len(&cbb))
            }

            /// Encapsulate a shared secret.
            ///
            /// - Returns: The shared secret and its encapsulated version.
            func encapsulate() -> KEM.EncapsulationResult {
                withUnsafeTemporaryAllocation(
                    of: UInt8.self, capacity: MLKEM.ciphertextSizeInBytes
                ) { encapsulatedPtr in
                    withUnsafeTemporaryAllocation(
                        of: UInt8.self, capacity: MLKEM.sharedSecretSizeInBytes
                    ) { secretPtr in
                        CCryptoBoringSSL_MLKEM768_encap(
                            encapsulatedPtr.baseAddress,
                            secretPtr.baseAddress,
                            &self.key
                        )

                        return KEM.EncapsulationResult(
                            sharedSecret: SymmetricKey(
                                data: Data(bytes: secretPtr.baseAddress!, count: MLKEM.sharedSecretSizeInBytes)
                            ),
                            encapsulated: Data(bytes: encapsulatedPtr.baseAddress!, count: MLKEM.ciphertextSizeInBytes)
                        )
                    }
                }
            }

            /// The size of the public key in bytes.
            static let bytesCount = 1184
        }
    }
}

@available(macOS 14.0, *)
extension MLKEM {
    /// The size of the encapsulated shared secret in bytes.
    private static let ciphertextSizeInBytes = 1088
}

@available(macOS 14.0, *)
extension MLKEM {
    /// The size of the seed in bytes.
    private static let seedSizeInBytes = 64

    // The size of the shared secret in bytes.
    private static let sharedSecretSizeInBytes = 32
}
