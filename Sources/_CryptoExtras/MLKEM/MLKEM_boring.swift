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

// MARK: - Generated file, do NOT edit
// any edits of this file WILL be overwritten and thus discarded
// see section `gyb` in `README` for details.

@_implementationOnly import CCryptoBoringSSL
import Crypto
import Foundation

/// A module-lattice-based key encapsulation mechanism that provides security against quantum computing attacks.
@available(macOS 14.0, iOS 17, watchOS 10, tvOS 17, macCatalyst 17, visionOS 1.0, *)
public enum MLKEM768 {}

@available(macOS 14.0, iOS 17, watchOS 10, tvOS 17, macCatalyst 17, visionOS 1.0, *)
extension MLKEM768 {
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
        public static func generate() -> MLKEM768.PrivateKey {
            .init()
        }

        /// Initialize a ML-KEM-768 private key from a seed.
        ///
        /// - Parameter seedRepresentation: The seed to use to generate the private key.
        ///
        /// - Throws: `CryptoKitError.incorrectKeySize` if the seed is not 64 bytes long.
        public init(seedRepresentation: some DataProtocol) throws {
            self.backing = try Backing(seedRepresentation: seedRepresentation)
        }

        /// The seed from which this private key was generated.
        public var seedRepresentation: Data {
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
        public func decapsulate(_ encapsulated: some DataProtocol) throws -> SymmetricKey {
            try self.backing.decapsulate(encapsulated)
        }

        fileprivate final class Backing {
            var key: MLKEM768_private_key
            var seed: Data

            /// Initialize a ML-KEM-768 private key from a random seed.
            init() {
                self.key = .init()
                self.seed = Data()

                self.seed = withUnsafeTemporaryAllocation(
                    of: UInt8.self,
                    capacity: MLKEM.seedByteCount
                ) { seedPtr in
                    withUnsafeTemporaryAllocation(
                        of: UInt8.self,
                        capacity: MLKEM768.PublicKey.byteCount
                    ) { publicKeyPtr in
                        CCryptoBoringSSL_MLKEM768_generate_key(
                            publicKeyPtr.baseAddress,
                            seedPtr.baseAddress,
                            &self.key
                        )

                        return Data(bytes: seedPtr.baseAddress!, count: MLKEM.seedByteCount)
                    }
                }
            }

            /// Initialize a ML-KEM-768 private key from a seed.
            ///
            /// - Parameter seedRepresentation: The seed to use to generate the private key.
            ///
            /// - Throws: `CryptoKitError.incorrectKeySize` if the seed is not 64 bytes long.
            init(seedRepresentation: some DataProtocol) throws {
                guard seedRepresentation.count == MLKEM.seedByteCount else {
                    throw CryptoKitError.incorrectKeySize
                }

                self.key = .init()
                self.seed = Data(seedRepresentation)

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
            func decapsulate(_ encapsulated: some DataProtocol) throws -> SymmetricKey {
                guard encapsulated.count == MLKEM768.ciphertextByteCount else {
                    throw CryptoKitError.incorrectParameterSize
                }

                var symmetricKeyData = Data(repeating: 0, count: MLKEM.sharedSecretByteCount)

                let rc: CInt = symmetricKeyData.withUnsafeMutableBytes { symmetricKeyDataPtr in
                    let bytes: ContiguousBytes =
                        encapsulated.regions.count == 1
                        ? encapsulated.regions.first!
                        : Array(encapsulated)
                    return bytes.withUnsafeBytes { encapsulatedPtr in
                        CCryptoBoringSSL_MLKEM768_decap(
                            symmetricKeyDataPtr.baseAddress,
                            encapsulatedPtr.baseAddress,
                            encapsulatedPtr.count,
                            &self.key
                        )
                    }
                }

                guard rc == 1 else {
                    throw CryptoKitError.internalBoringSSLError()
                }

                return SymmetricKey(data: symmetricKeyData)
            }
        }
    }
}

@available(macOS 14.0, iOS 17, watchOS 10, tvOS 17, macCatalyst 17, visionOS 1.0, *)
extension MLKEM768 {
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
        public init(rawRepresentation: some DataProtocol) throws {
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
        static let byteCount = Backing.byteCount

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
                guard rawRepresentation.count == MLKEM768.PublicKey.byteCount else {
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
                CCryptoBoringSSL_CBB_init(&cbb, MLKEM768.PublicKey.Backing.byteCount)
                defer { CCryptoBoringSSL_CBB_cleanup(&cbb) }
                CCryptoBoringSSL_MLKEM768_marshal_public_key(&cbb, &self.key)
                return Data(bytes: CCryptoBoringSSL_CBB_data(&cbb), count: CCryptoBoringSSL_CBB_len(&cbb))
            }

            /// Encapsulate a shared secret.
            ///
            /// - Returns: The shared secret and its encapsulated version.
            func encapsulate() -> KEM.EncapsulationResult {
                withUnsafeTemporaryAllocation(
                    of: UInt8.self,
                    capacity: MLKEM768.ciphertextByteCount
                ) { encapsulatedPtr in
                    withUnsafeTemporaryAllocation(
                        of: UInt8.self,
                        capacity: MLKEM.sharedSecretByteCount
                    ) { secretPtr in
                        CCryptoBoringSSL_MLKEM768_encap(
                            encapsulatedPtr.baseAddress,
                            secretPtr.baseAddress,
                            &self.key
                        )

                        return KEM.EncapsulationResult(
                            sharedSecret: SymmetricKey(
                                data: Data(bytes: secretPtr.baseAddress!, count: MLKEM.sharedSecretByteCount)
                            ),
                            encapsulated: Data(
                                bytes: encapsulatedPtr.baseAddress!,
                                count: MLKEM768.ciphertextByteCount
                            )
                        )
                    }
                }
            }

            /// The size of the public key in bytes.
            static let byteCount = Int(MLKEM768_PUBLIC_KEY_BYTES)
        }
    }
}

@available(macOS 14.0, iOS 17, watchOS 10, tvOS 17, macCatalyst 17, visionOS 1.0, *)
extension MLKEM768 {
    /// The size of the encapsulated shared secret in bytes.
    private static let ciphertextByteCount = Int(MLKEM768_CIPHERTEXT_BYTES)
}

/// A module-lattice-based key encapsulation mechanism that provides security against quantum computing attacks.
@available(macOS 14.0, iOS 17, watchOS 10, tvOS 17, macCatalyst 17, visionOS 1.0, *)
public enum MLKEM1024 {}

@available(macOS 14.0, iOS 17, watchOS 10, tvOS 17, macCatalyst 17, visionOS 1.0, *)
extension MLKEM1024 {
    /// A ML-KEM-1024 private key.
    public struct PrivateKey: Sendable, KEMPrivateKey {
        private var backing: Backing

        /// Initialize a ML-KEM-1024 private key from a random seed.
        public init() {
            self.backing = Backing()
        }

        /// Generate a ML-KEM-1024 private key from a random seed.
        ///
        /// - Returns: The generated private key.
        public static func generate() -> MLKEM1024.PrivateKey {
            .init()
        }

        /// Initialize a ML-KEM-1024 private key from a seed.
        ///
        /// - Parameter seedRepresentation: The seed to use to generate the private key.
        ///
        /// - Throws: `CryptoKitError.incorrectKeySize` if the seed is not 64 bytes long.
        public init(seedRepresentation: some DataProtocol) throws {
            self.backing = try Backing(seedRepresentation: seedRepresentation)
        }

        /// The seed from which this private key was generated.
        public var seedRepresentation: Data {
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
        public func decapsulate(_ encapsulated: some DataProtocol) throws -> SymmetricKey {
            try self.backing.decapsulate(encapsulated)
        }

        fileprivate final class Backing {
            var key: MLKEM1024_private_key
            var seed: Data

            /// Initialize a ML-KEM-1024 private key from a random seed.
            init() {
                self.key = .init()
                self.seed = Data()

                self.seed = withUnsafeTemporaryAllocation(
                    of: UInt8.self,
                    capacity: MLKEM.seedByteCount
                ) { seedPtr in
                    withUnsafeTemporaryAllocation(
                        of: UInt8.self,
                        capacity: MLKEM1024.PublicKey.byteCount
                    ) { publicKeyPtr in
                        CCryptoBoringSSL_MLKEM1024_generate_key(
                            publicKeyPtr.baseAddress,
                            seedPtr.baseAddress,
                            &self.key
                        )

                        return Data(bytes: seedPtr.baseAddress!, count: MLKEM.seedByteCount)
                    }
                }
            }

            /// Initialize a ML-KEM-1024 private key from a seed.
            ///
            /// - Parameter seedRepresentation: The seed to use to generate the private key.
            ///
            /// - Throws: `CryptoKitError.incorrectKeySize` if the seed is not 64 bytes long.
            init(seedRepresentation: some DataProtocol) throws {
                guard seedRepresentation.count == MLKEM.seedByteCount else {
                    throw CryptoKitError.incorrectKeySize
                }

                self.key = .init()
                self.seed = Data(seedRepresentation)

                guard
                    self.seed.withUnsafeBytes({ seedPtr in
                        CCryptoBoringSSL_MLKEM1024_private_key_from_seed(
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
            func decapsulate(_ encapsulated: some DataProtocol) throws -> SymmetricKey {
                guard encapsulated.count == MLKEM1024.ciphertextByteCount else {
                    throw CryptoKitError.incorrectParameterSize
                }

                var symmetricKeyData = Data(repeating: 0, count: MLKEM.sharedSecretByteCount)

                let rc: CInt = symmetricKeyData.withUnsafeMutableBytes { symmetricKeyDataPtr in
                    let bytes: ContiguousBytes =
                        encapsulated.regions.count == 1
                        ? encapsulated.regions.first!
                        : Array(encapsulated)
                    return bytes.withUnsafeBytes { encapsulatedPtr in
                        CCryptoBoringSSL_MLKEM1024_decap(
                            symmetricKeyDataPtr.baseAddress,
                            encapsulatedPtr.baseAddress,
                            encapsulatedPtr.count,
                            &self.key
                        )
                    }
                }

                guard rc == 1 else {
                    throw CryptoKitError.internalBoringSSLError()
                }

                return SymmetricKey(data: symmetricKeyData)
            }
        }
    }
}

@available(macOS 14.0, iOS 17, watchOS 10, tvOS 17, macCatalyst 17, visionOS 1.0, *)
extension MLKEM1024 {
    /// A ML-KEM-1024 public key.
    public struct PublicKey: Sendable, KEMPublicKey {
        private var backing: Backing

        fileprivate init(privateKeyBacking: PrivateKey.Backing) {
            self.backing = Backing(privateKeyBacking: privateKeyBacking)
        }

        /// Initialize a ML-KEM-1024 public key from a raw representation.
        ///
        /// - Parameter rawRepresentation: The public key bytes.
        ///
        /// - Throws: `CryptoKitError.incorrectKeySize` if the raw representation is not the correct size.
        public init(rawRepresentation: some DataProtocol) throws {
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
        static let byteCount = Backing.byteCount

        fileprivate final class Backing {
            var key: MLKEM1024_public_key

            init(privateKeyBacking: PrivateKey.Backing) {
                self.key = .init()
                CCryptoBoringSSL_MLKEM1024_public_from_private(&self.key, &privateKeyBacking.key)
            }

            /// Initialize a ML-KEM-1024 public key from a raw representation.
            ///
            /// - Parameter rawRepresentation: The public key bytes.
            ///
            /// - Throws: `CryptoKitError.incorrectKeySize` if the raw representation is not the correct size.
            init(rawRepresentation: some DataProtocol) throws {
                guard rawRepresentation.count == MLKEM1024.PublicKey.byteCount else {
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
                        guard CCryptoBoringSSL_MLKEM1024_parse_public_key(&self.key, &cbs) == 1 else {
                            throw CryptoKitError.internalBoringSSLError()
                        }
                    }
                }
            }

            /// The raw binary representation of the public key.
            var rawRepresentation: Data {
                var cbb = CBB()
                // The following BoringSSL functions can only fail on allocation failure, which we define as impossible.
                CCryptoBoringSSL_CBB_init(&cbb, MLKEM1024.PublicKey.Backing.byteCount)
                defer { CCryptoBoringSSL_CBB_cleanup(&cbb) }
                CCryptoBoringSSL_MLKEM1024_marshal_public_key(&cbb, &self.key)
                return Data(bytes: CCryptoBoringSSL_CBB_data(&cbb), count: CCryptoBoringSSL_CBB_len(&cbb))
            }

            /// Encapsulate a shared secret.
            ///
            /// - Returns: The shared secret and its encapsulated version.
            func encapsulate() -> KEM.EncapsulationResult {
                withUnsafeTemporaryAllocation(
                    of: UInt8.self,
                    capacity: MLKEM1024.ciphertextByteCount
                ) { encapsulatedPtr in
                    withUnsafeTemporaryAllocation(
                        of: UInt8.self,
                        capacity: MLKEM.sharedSecretByteCount
                    ) { secretPtr in
                        CCryptoBoringSSL_MLKEM1024_encap(
                            encapsulatedPtr.baseAddress,
                            secretPtr.baseAddress,
                            &self.key
                        )

                        return KEM.EncapsulationResult(
                            sharedSecret: SymmetricKey(
                                data: Data(bytes: secretPtr.baseAddress!, count: MLKEM.sharedSecretByteCount)
                            ),
                            encapsulated: Data(
                                bytes: encapsulatedPtr.baseAddress!,
                                count: MLKEM1024.ciphertextByteCount
                            )
                        )
                    }
                }
            }

            /// The size of the public key in bytes.
            static let byteCount = Int(MLKEM1024_PUBLIC_KEY_BYTES)
        }
    }
}

@available(macOS 14.0, iOS 17, watchOS 10, tvOS 17, macCatalyst 17, visionOS 1.0, *)
extension MLKEM1024 {
    /// The size of the encapsulated shared secret in bytes.
    private static let ciphertextByteCount = Int(MLKEM1024_CIPHERTEXT_BYTES)
}

private enum MLKEM {
    /// The size of the seed in bytes.
    fileprivate static let seedByteCount = 64

    // The size of the shared secret in bytes.
    fileprivate static let sharedSecretByteCount = 32
}
