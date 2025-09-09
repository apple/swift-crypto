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

#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
@_implementationOnly import CCryptoBoringSSL
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// MARK: - Generated file, do NOT edit
// any edits of this file WILL be overwritten and thus discarded
// see section `gyb` in `README` for details.

@_implementationOnly import CCryptoBoringSSL
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLDSA65 {
    /// A ML-DSA-65 private key.
    struct InternalPrivateKey: @unchecked Sendable {
        private var backing: Backing

        /// Initialize a ML-DSA-65 private key from a random seed.
        init() throws {
            self.backing = try Backing()
        }

        /// Initialize a ML-DSA-65 private key from a seed.
        ///
        /// - Parameter seedRepresentation: The seed to use to generate the private key.
        ///
        /// - Throws: `CryptoKitError.incorrectKeySize` if the seed is not 32 bytes long.
        init(seedRepresentation: some DataProtocol) throws {
            self.backing = try Backing(seedRepresentation: seedRepresentation)
        }

        /// The seed from which this private key was generated.
        var seedRepresentation: Data {
            self.backing.seed
        }

        /// The public key associated with this private key.
        var publicKey: InternalPublicKey {
            self.backing.publicKey
        }

        /// Generate a signature for the given data.
        ///
        /// - Parameter data: The message to sign.
        ///
        /// - Returns: The signature of the message.
        func signature<D: DataProtocol>(for data: D) throws -> Data {
            let context: Data? = nil
            return try self.backing.signature(for: data, context: context)
        }

        /// Generate a signature for the given data.
        ///
        /// - Parameters:
        ///   - data: The message to sign.
        ///   - context: The context to use for the signature.
        ///
        /// - Returns: The signature of the message.
        func signature<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data {
            try self.backing.signature(for: data, context: context)
        }

        /// The size of the private key in bytes.
        static let byteCount = Backing.byteCount

        fileprivate final class Backing {
            fileprivate var key: MLDSA65_private_key
            var seed: Data

            /// Initialize a ML-DSA-65 private key from a random seed.
            init() throws {
                // We have to initialize all members before `self` is captured by the closure
                self.key = .init()
                self.seed = Data()

                self.seed = try withUnsafeTemporaryAllocation(
                    of: UInt8.self,
                    capacity: MLDSA.seedByteCount
                ) { seedPtr in
                    try withUnsafeTemporaryAllocation(
                        of: UInt8.self,
                        capacity: MLDSA65.InternalPublicKey.Backing.byteCount
                    ) { publicKeyPtr in
                        guard
                            CCryptoBoringSSL_MLDSA65_generate_key(
                                publicKeyPtr.baseAddress,
                                seedPtr.baseAddress,
                                &self.key
                            ) == 1
                        else {
                            throw CryptoKitError.internalBoringSSLError()
                        }

                        return Data(bytes: seedPtr.baseAddress!, count: MLDSA.seedByteCount)
                    }
                }
            }

            /// Initialize a ML-DSA-65 private key from a seed.
            ///
            /// - Parameter seedRepresentation: The seed to use to generate the private key.
            ///
            /// - Throws: `CryptoKitError.incorrectKeySize` if the seed is not 32 bytes long.
            init(seedRepresentation: some DataProtocol) throws {
                guard seedRepresentation.count == MLDSA.seedByteCount else {
                    throw CryptoKitError.incorrectKeySize
                }

                self.key = .init()
                self.seed = Data(seedRepresentation)

                guard
                    self.seed.withUnsafeBytes({ seedPtr in
                        CCryptoBoringSSL_MLDSA65_private_key_from_seed(
                            &self.key,
                            seedPtr.baseAddress,
                            MLDSA.seedByteCount
                        )
                    }) == 1
                else {
                    throw CryptoKitError.internalBoringSSLError()
                }
            }

            /// The public key associated with this private key.
            var publicKey: InternalPublicKey {
                InternalPublicKey(privateKeyBacking: self)
            }

            /// Generate a signature for the given data.
            ///
            /// - Parameters:
            ///   - data: The message to sign.
            ///   - context: The context to use for the signature.
            ///
            /// - Returns: The signature of the message.
            func signature<D: DataProtocol, C: DataProtocol>(for data: D, context: C?) throws -> Data {
                var signature = Data(repeating: 0, count: MLDSA65.signatureByteCount)

                let rc: CInt = signature.withUnsafeMutableBytes { signaturePtr in
                    let bytes: ContiguousBytes = data.regions.count == 1 ? data.regions.first! : Array(data)
                    return bytes.withUnsafeBytes { dataPtr in
                        context.withUnsafeBytes { contextPtr in
                            CCryptoBoringSSL_MLDSA65_sign(
                                signaturePtr.baseAddress,
                                &self.key,
                                dataPtr.baseAddress,
                                dataPtr.count,
                                contextPtr.baseAddress,
                                contextPtr.count
                            )
                        }
                    }
                }

                guard rc == 1 else {
                    throw CryptoKitError.internalBoringSSLError()
                }

                return signature
            }

            /// The size of the private key in bytes.
            static let byteCount = Int(MLDSA65_PRIVATE_KEY_BYTES)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLDSA65 {
    /// A ML-DSA-65 public key.
    struct InternalPublicKey: @unchecked Sendable {
        private var backing: Backing

        fileprivate init(privateKeyBacking: InternalPrivateKey.Backing) {
            self.backing = Backing(privateKeyBacking: privateKeyBacking)
        }

        /// Initialize a ML-DSA-65 public key from a raw representation.
        ///
        /// - Parameter rawRepresentation: The public key bytes.
        ///
        /// - Throws: `CryptoKitError.incorrectKeySize` if the raw representation is not the correct size.
        init(rawRepresentation: some DataProtocol) throws {
            self.backing = try Backing(rawRepresentation: rawRepresentation)
        }

        /// The raw binary representation of the public key.
        var rawRepresentation: Data {
            self.backing.rawRepresentation
        }

        /// Verify a signature for the given data.
        ///
        /// - Parameters:
        ///   - signature: The signature to verify.
        ///   - data: The message to verify the signature against.
        ///
        /// - Returns: `true` if the signature is valid, `false` otherwise.
        func isValidSignature<S: DataProtocol, D: DataProtocol>(_ signature: S, for data: D) -> Bool {
            let context: Data? = nil
            return self.backing.isValidSignature(signature, for: data, context: context)
        }

        /// Verify a signature for the given data.
        ///
        /// - Parameters:
        ///   - signature: The signature to verify.
        ///   - data: The message to verify the signature against.
        ///   - context: The context to use for the signature verification.
        ///
        /// - Returns: `true` if the signature is valid, `false` otherwise.
        func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(
            _ signature: S,
            for data: D,
            context: C
        ) -> Bool {
            self.backing.isValidSignature(signature, for: data, context: context)
        }

        /// The size of the public key in bytes.
        static let byteCount = Backing.byteCount

        fileprivate final class Backing {
            private var key: MLDSA65_public_key

            init(privateKeyBacking: InternalPrivateKey.Backing) {
                self.key = .init()
                CCryptoBoringSSL_MLDSA65_public_from_private(&self.key, &privateKeyBacking.key)
            }

            /// Initialize a ML-DSA-65 public key from a raw representation.
            ///
            /// - Parameter rawRepresentation: The public key bytes.
            ///
            /// - Throws: `CryptoKitError.incorrectKeySize` if the raw representation is not the correct size.
            init(rawRepresentation: some DataProtocol) throws {
                guard rawRepresentation.count == MLDSA65.InternalPublicKey.Backing.byteCount else {
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
                        guard CCryptoBoringSSL_MLDSA65_parse_public_key(&self.key, &cbs) == 1 else {
                            throw CryptoKitError.internalBoringSSLError()
                        }
                    }
                }
            }

            /// The raw binary representation of the public key.
            var rawRepresentation: Data {
                var cbb = CBB()
                // The following BoringSSL functions can only fail on allocation failure, which we define as impossible.
                CCryptoBoringSSL_CBB_init(&cbb, MLDSA65.InternalPublicKey.Backing.byteCount)
                defer { CCryptoBoringSSL_CBB_cleanup(&cbb) }
                CCryptoBoringSSL_MLDSA65_marshal_public_key(&cbb, &self.key)
                return Data(bytes: CCryptoBoringSSL_CBB_data(&cbb), count: CCryptoBoringSSL_CBB_len(&cbb))
            }

            /// Verify a signature for the given data.
            ///
            /// - Parameters:
            ///   - signature: The signature to verify.
            ///   - data: The message to verify the signature against.
            ///   - context: The context to use for the signature verification.
            ///
            /// - Returns: `true` if the signature is valid, `false` otherwise.
            func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(
                _ signature: S,
                for data: D,
                context: C?
            ) -> Bool {
                let signatureBytes: ContiguousBytes =
                    signature.regions.count == 1 ? signature.regions.first! : Array(signature)
                return signatureBytes.withUnsafeBytes { signaturePtr in
                    let dataBytes: ContiguousBytes = data.regions.count == 1 ? data.regions.first! : Array(data)
                    let rc: CInt = dataBytes.withUnsafeBytes { dataPtr in
                        context.withUnsafeBytes { contextPtr in
                            CCryptoBoringSSL_MLDSA65_verify(
                                &self.key,
                                signaturePtr.baseAddress,
                                signaturePtr.count,
                                dataPtr.baseAddress,
                                dataPtr.count,
                                contextPtr.baseAddress,
                                contextPtr.count
                            )
                        }
                    }
                    return rc == 1
                }
            }

            /// The size of the public key in bytes.
            static let byteCount = Int(MLDSA65_PUBLIC_KEY_BYTES)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLDSA65 {
    /// The size of the signature in bytes.
    private static let signatureByteCount = Int(MLDSA65_SIGNATURE_BYTES)
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLDSA87 {
    /// A ML-DSA-87 private key.
    struct InternalPrivateKey: @unchecked Sendable {
        private var backing: Backing

        /// Initialize a ML-DSA-87 private key from a random seed.
        init() throws {
            self.backing = try Backing()
        }

        /// Initialize a ML-DSA-87 private key from a seed.
        ///
        /// - Parameter seedRepresentation: The seed to use to generate the private key.
        ///
        /// - Throws: `CryptoKitError.incorrectKeySize` if the seed is not 32 bytes long.
        init(seedRepresentation: some DataProtocol) throws {
            self.backing = try Backing(seedRepresentation: seedRepresentation)
        }

        /// The seed from which this private key was generated.
        var seedRepresentation: Data {
            self.backing.seed
        }

        /// The public key associated with this private key.
        var publicKey: InternalPublicKey {
            self.backing.publicKey
        }

        /// Generate a signature for the given data.
        ///
        /// - Parameter data: The message to sign.
        ///
        /// - Returns: The signature of the message.
        func signature<D: DataProtocol>(for data: D) throws -> Data {
            let context: Data? = nil
            return try self.backing.signature(for: data, context: context)
        }

        /// Generate a signature for the given data.
        ///
        /// - Parameters:
        ///   - data: The message to sign.
        ///   - context: The context to use for the signature.
        ///
        /// - Returns: The signature of the message.
        func signature<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data {
            try self.backing.signature(for: data, context: context)
        }

        /// The size of the private key in bytes.
        static let byteCount = Backing.byteCount

        fileprivate final class Backing {
            fileprivate var key: MLDSA87_private_key
            var seed: Data

            /// Initialize a ML-DSA-87 private key from a random seed.
            init() throws {
                // We have to initialize all members before `self` is captured by the closure
                self.key = .init()
                self.seed = Data()

                self.seed = try withUnsafeTemporaryAllocation(
                    of: UInt8.self,
                    capacity: MLDSA.seedByteCount
                ) { seedPtr in
                    try withUnsafeTemporaryAllocation(
                        of: UInt8.self,
                        capacity: MLDSA87.InternalPublicKey.Backing.byteCount
                    ) { publicKeyPtr in
                        guard
                            CCryptoBoringSSL_MLDSA87_generate_key(
                                publicKeyPtr.baseAddress,
                                seedPtr.baseAddress,
                                &self.key
                            ) == 1
                        else {
                            throw CryptoKitError.internalBoringSSLError()
                        }

                        return Data(bytes: seedPtr.baseAddress!, count: MLDSA.seedByteCount)
                    }
                }
            }

            /// Initialize a ML-DSA-87 private key from a seed.
            ///
            /// - Parameter seedRepresentation: The seed to use to generate the private key.
            ///
            /// - Throws: `CryptoKitError.incorrectKeySize` if the seed is not 32 bytes long.
            init(seedRepresentation: some DataProtocol) throws {
                guard seedRepresentation.count == MLDSA.seedByteCount else {
                    throw CryptoKitError.incorrectKeySize
                }

                self.key = .init()
                self.seed = Data(seedRepresentation)

                guard
                    self.seed.withUnsafeBytes({ seedPtr in
                        CCryptoBoringSSL_MLDSA87_private_key_from_seed(
                            &self.key,
                            seedPtr.baseAddress,
                            MLDSA.seedByteCount
                        )
                    }) == 1
                else {
                    throw CryptoKitError.internalBoringSSLError()
                }
            }

            /// The public key associated with this private key.
            var publicKey: InternalPublicKey {
                InternalPublicKey(privateKeyBacking: self)
            }

            /// Generate a signature for the given data.
            ///
            /// - Parameters:
            ///   - data: The message to sign.
            ///   - context: The context to use for the signature.
            ///
            /// - Returns: The signature of the message.
            func signature<D: DataProtocol, C: DataProtocol>(for data: D, context: C?) throws -> Data {
                var signature = Data(repeating: 0, count: MLDSA87.signatureByteCount)

                let rc: CInt = signature.withUnsafeMutableBytes { signaturePtr in
                    let bytes: ContiguousBytes = data.regions.count == 1 ? data.regions.first! : Array(data)
                    return bytes.withUnsafeBytes { dataPtr in
                        context.withUnsafeBytes { contextPtr in
                            CCryptoBoringSSL_MLDSA87_sign(
                                signaturePtr.baseAddress,
                                &self.key,
                                dataPtr.baseAddress,
                                dataPtr.count,
                                contextPtr.baseAddress,
                                contextPtr.count
                            )
                        }
                    }
                }

                guard rc == 1 else {
                    throw CryptoKitError.internalBoringSSLError()
                }

                return signature
            }

            /// The size of the private key in bytes.
            static let byteCount = Int(MLDSA87_PRIVATE_KEY_BYTES)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLDSA87 {
    /// A ML-DSA-87 public key.
    struct InternalPublicKey: @unchecked Sendable {
        private var backing: Backing

        fileprivate init(privateKeyBacking: InternalPrivateKey.Backing) {
            self.backing = Backing(privateKeyBacking: privateKeyBacking)
        }

        /// Initialize a ML-DSA-87 public key from a raw representation.
        ///
        /// - Parameter rawRepresentation: The public key bytes.
        ///
        /// - Throws: `CryptoKitError.incorrectKeySize` if the raw representation is not the correct size.
        init(rawRepresentation: some DataProtocol) throws {
            self.backing = try Backing(rawRepresentation: rawRepresentation)
        }

        /// The raw binary representation of the public key.
        var rawRepresentation: Data {
            self.backing.rawRepresentation
        }

        /// Verify a signature for the given data.
        ///
        /// - Parameters:
        ///   - signature: The signature to verify.
        ///   - data: The message to verify the signature against.
        ///
        /// - Returns: `true` if the signature is valid, `false` otherwise.
        func isValidSignature<S: DataProtocol, D: DataProtocol>(_ signature: S, for data: D) -> Bool {
            let context: Data? = nil
            return self.backing.isValidSignature(signature, for: data, context: context)
        }

        /// Verify a signature for the given data.
        ///
        /// - Parameters:
        ///   - signature: The signature to verify.
        ///   - data: The message to verify the signature against.
        ///   - context: The context to use for the signature verification.
        ///
        /// - Returns: `true` if the signature is valid, `false` otherwise.
        func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(
            _ signature: S,
            for data: D,
            context: C
        ) -> Bool {
            self.backing.isValidSignature(signature, for: data, context: context)
        }

        /// The size of the public key in bytes.
        static let byteCount = Backing.byteCount

        fileprivate final class Backing {
            private var key: MLDSA87_public_key

            init(privateKeyBacking: InternalPrivateKey.Backing) {
                self.key = .init()
                CCryptoBoringSSL_MLDSA87_public_from_private(&self.key, &privateKeyBacking.key)
            }

            /// Initialize a ML-DSA-87 public key from a raw representation.
            ///
            /// - Parameter rawRepresentation: The public key bytes.
            ///
            /// - Throws: `CryptoKitError.incorrectKeySize` if the raw representation is not the correct size.
            init(rawRepresentation: some DataProtocol) throws {
                guard rawRepresentation.count == MLDSA87.InternalPublicKey.Backing.byteCount else {
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
                        guard CCryptoBoringSSL_MLDSA87_parse_public_key(&self.key, &cbs) == 1 else {
                            throw CryptoKitError.internalBoringSSLError()
                        }
                    }
                }
            }

            /// The raw binary representation of the public key.
            var rawRepresentation: Data {
                var cbb = CBB()
                // The following BoringSSL functions can only fail on allocation failure, which we define as impossible.
                CCryptoBoringSSL_CBB_init(&cbb, MLDSA87.InternalPublicKey.Backing.byteCount)
                defer { CCryptoBoringSSL_CBB_cleanup(&cbb) }
                CCryptoBoringSSL_MLDSA87_marshal_public_key(&cbb, &self.key)
                return Data(bytes: CCryptoBoringSSL_CBB_data(&cbb), count: CCryptoBoringSSL_CBB_len(&cbb))
            }

            /// Verify a signature for the given data.
            ///
            /// - Parameters:
            ///   - signature: The signature to verify.
            ///   - data: The message to verify the signature against.
            ///   - context: The context to use for the signature verification.
            ///
            /// - Returns: `true` if the signature is valid, `false` otherwise.
            func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(
                _ signature: S,
                for data: D,
                context: C?
            ) -> Bool {
                let signatureBytes: ContiguousBytes =
                    signature.regions.count == 1 ? signature.regions.first! : Array(signature)
                return signatureBytes.withUnsafeBytes { signaturePtr in
                    let dataBytes: ContiguousBytes = data.regions.count == 1 ? data.regions.first! : Array(data)
                    let rc: CInt = dataBytes.withUnsafeBytes { dataPtr in
                        context.withUnsafeBytes { contextPtr in
                            CCryptoBoringSSL_MLDSA87_verify(
                                &self.key,
                                signaturePtr.baseAddress,
                                signaturePtr.count,
                                dataPtr.baseAddress,
                                dataPtr.count,
                                contextPtr.baseAddress,
                                contextPtr.count
                            )
                        }
                    }
                    return rc == 1
                }
            }

            /// The size of the public key in bytes.
            static let byteCount = Int(MLDSA87_PUBLIC_KEY_BYTES)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLDSA87 {
    /// The size of the signature in bytes.
    private static let signatureByteCount = Int(MLDSA87_SIGNATURE_BYTES)
}

enum MLDSA {
    /// The size of the seed in bytes.
    static let seedByteCount = 32
}

#endif  // CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
