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

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A stateless hash-based digital signature algorithm that provides security against quantum computing attacks.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public enum SLHDSA {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SLHDSA {
    /// The SLH-DSA-SHA2-128s parameter set.
    public enum SHA2_128s {}
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SLHDSA.SHA2_128s {
    /// A SLH-DSA-SHA2-128s private key.
    public struct PrivateKey: Sendable {
        private var backing: Backing

        /// Initialize a SLH-DSA-SHA2-128s private key from a random seed.
        public init() {
            self.backing = Backing()
        }

        /// Initialize a SLH-DSA-SHA2-128s private key from a raw representation.
        ///
        /// - Parameter rawRepresentation: The private key bytes.
        ///
        /// - Throws: `CryptoKitError.incorrectKeySize` if the raw representation is not the correct size.
        public init(rawRepresentation: some DataProtocol) throws {
            self.backing = try Backing(rawRepresentation: rawRepresentation)
        }

        /// The raw representation of the private key.
        public var rawRepresentation: Data {
            self.backing.rawRepresentation
        }

        /// The public key associated with this private key.
        public var publicKey: PublicKey {
            self.backing.publicKey
        }

        /// Generate a signature for the given data.
        ///
        /// - Parameter data: The message to sign.
        ///
        /// - Returns: The signature of the message.
        public func signature<D: DataProtocol>(for data: D) throws -> Data {
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
        public func signature<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data {
            try self.backing.signature(for: data, context: context)
        }

        fileprivate final class Backing {
            private let pointer: UnsafeMutableBufferPointer<UInt8>

            func withUnsafePointer<T>(_ body: (UnsafePointer<UInt8>) throws -> T) rethrows -> T {
                try body(self.pointer.baseAddress!)
            }

            /// Initialize a SLH-DSA-SHA2-128s private key from a random seed.
            init() {
                self.pointer = UnsafeMutableBufferPointer<UInt8>.allocate(
                    capacity: SLHDSA.SHA2_128s.PrivateKey.Backing.byteCount
                )

                withUnsafeTemporaryAllocation(
                    of: UInt8.self,
                    capacity: SLHDSA.SHA2_128s.PublicKey.Backing.byteCount
                ) { publicKeyPtr in
                    CCryptoBoringSSL_SLHDSA_SHA2_128S_generate_key(publicKeyPtr.baseAddress, self.pointer.baseAddress)
                }
            }

            /// Initialize a SLH-DSA-SHA2-128s private key from a raw representation.
            ///
            /// - Parameter rawRepresentation: The private key bytes.
            ///
            /// - Throws: `CryptoKitError.incorrectKeySize` if the raw representation is not the correct size.
            init(rawRepresentation: some DataProtocol) throws {
                guard rawRepresentation.count == SLHDSA.SHA2_128s.PrivateKey.Backing.byteCount else {
                    throw CryptoKitError.incorrectKeySize
                }

                self.pointer = UnsafeMutableBufferPointer<UInt8>.allocate(
                    capacity: SLHDSA.SHA2_128s.PrivateKey.Backing.byteCount
                )
                _ = self.pointer.initialize(fromContentsOf: rawRepresentation)
            }

            /// The raw representation of the private key.
            var rawRepresentation: Data {
                Data(
                    UnsafeBufferPointer(
                        start: self.pointer.baseAddress,
                        count: SLHDSA.SHA2_128s.PrivateKey.Backing.byteCount
                    )
                )
            }

            /// The public key associated with this private key.
            var publicKey: PublicKey {
                PublicKey(privateKeyBacking: self)
            }

            /// Generate a signature for the given data.
            ///
            /// - Parameters:
            ///   - data: The message to sign.
            ///   - context: The context to use for the signature.
            ///
            /// - Returns: The signature of the message.
            func signature<D: DataProtocol, C: DataProtocol>(for data: D, context: C?) throws -> Data {
                var signature = Data(repeating: 0, count: SLHDSA.SHA2_128s.signatureByteCount)

                let rc: CInt = signature.withUnsafeMutableBytes { signaturePtr in
                    let bytes: ContiguousBytes = data.regions.count == 1 ? data.regions.first! : Array(data)
                    return bytes.withUnsafeBytes { dataPtr in
                        context.withUnsafeBytes { contextPtr in
                            CCryptoBoringSSL_SLHDSA_SHA2_128S_sign(
                                signaturePtr.baseAddress,
                                self.pointer.baseAddress,
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
            static let byteCount = 64
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SLHDSA.SHA2_128s {
    /// A SLH-DSA-SHA2-128s public key.
    public struct PublicKey: Sendable {
        private var backing: Backing

        fileprivate init(privateKeyBacking: PrivateKey.Backing) {
            self.backing = Backing(privateKeyBacking: privateKeyBacking)
        }

        /// Initialize a SLH-DSA-SHA2-128s public key from a raw representation.
        ///
        /// - Parameter rawRepresentation: The public key bytes.
        ///
        /// - Throws: `CryptoKitError.incorrectKeySize` if the raw representation is not the correct size.
        public init(rawRepresentation: some DataProtocol) throws {
            self.backing = try Backing(rawRepresentation: rawRepresentation)
        }

        /// The raw representation of the public key.
        public var rawRepresentation: Data {
            self.backing.rawRepresentation
        }

        /// Verify a signature for the given data.
        ///
        /// - Parameters:
        ///   - signature: The signature to verify.
        ///   - data: The message to verify the signature against.
        ///
        /// - Returns: `true` if the signature is valid, `false` otherwise.
        public func isValidSignature<S: DataProtocol, D: DataProtocol>(
            _ signature: S,
            for data: D
        ) -> Bool {
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
        public func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(
            _ signature: S,
            for data: D,
            context: C
        ) -> Bool {
            self.backing.isValidSignature(signature, for: data, context: context)
        }

        fileprivate final class Backing {
            private let pointer: UnsafeMutableBufferPointer<UInt8>

            init(privateKeyBacking: PrivateKey.Backing) {
                self.pointer = UnsafeMutableBufferPointer<UInt8>.allocate(
                    capacity: SLHDSA.SHA2_128s.PublicKey.Backing.byteCount
                )
                privateKeyBacking.withUnsafePointer { privateKeyPtr in
                    CCryptoBoringSSL_SLHDSA_SHA2_128S_public_from_private(self.pointer.baseAddress, privateKeyPtr)
                }
            }

            /// Initialize a SLH-DSA-SHA2-128s public key from a raw representation.
            ///
            /// - Parameter rawRepresentation: The public key bytes.
            ///
            /// - Throws: `CryptoKitError.incorrectKeySize` if the raw representation is not the correct size.
            init(rawRepresentation: some DataProtocol) throws {
                guard rawRepresentation.count == SLHDSA.SHA2_128s.PublicKey.Backing.byteCount else {
                    throw CryptoKitError.incorrectKeySize
                }

                self.pointer = UnsafeMutableBufferPointer<UInt8>.allocate(
                    capacity: SLHDSA.SHA2_128s.PublicKey.Backing.byteCount
                )
                _ = self.pointer.initialize(fromContentsOf: rawRepresentation)
            }

            /// The raw representation of the public key.
            var rawRepresentation: Data {
                Data(
                    UnsafeBufferPointer(
                        start: self.pointer.baseAddress,
                        count: SLHDSA.SHA2_128s.PublicKey.Backing.byteCount
                    )
                )
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
                            CCryptoBoringSSL_SLHDSA_SHA2_128S_verify(
                                signaturePtr.baseAddress,
                                signaturePtr.count,
                                self.pointer.baseAddress,
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
            static let byteCount = 32
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SLHDSA.SHA2_128s {
    /// The size of the signature in bytes.
    private static let signatureByteCount = 7856
}
