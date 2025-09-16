//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftCrypto project authors
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

#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API

@_implementationOnly import CCryptoBoringSSL
import Crypto

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
extension MLDSA65.PrivateKey {
    struct ExternalMuPrivateKey: @unchecked Sendable {
        private var backing: Backing

        init(seedRepresentation: some DataProtocol) throws {
            self.backing = try Backing(seedRepresentation: seedRepresentation)
        }

        func signature(forPrehashedMessageRepresentative mu: some DataProtocol) throws -> Data {
            try self.backing.signature(forPrehashedMessageRepresentative: mu)
        }

        fileprivate final class Backing {
            fileprivate var key: MLDSA65_private_key

            init(seedRepresentation: some DataProtocol) throws {
                guard seedRepresentation.count == MLDSA.seedByteCount else {
                    throw CryptoKitError.incorrectKeySize
                }

                self.key = .init()

                guard
                    Data(seedRepresentation).withUnsafeBytes({ seedPtr in
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

            func signature(forPrehashedMessageRepresentative mu: some DataProtocol) throws -> Data {
                guard mu.count == MLDSA.muByteCount else {
                    throw CryptoKitError.incorrectParameterSize
                }

                var signature = Data(repeating: 0, count: Int(MLDSA65_SIGNATURE_BYTES))

                let rc: CInt = signature.withUnsafeMutableBytes { signaturePtr in
                    let muBytes: ContiguousBytes = mu.regions.count == 1 ? mu.regions.first! : Array(mu)
                    return muBytes.withUnsafeBytes { muPtr in
                        CCryptoBoringSSL_MLDSA65_sign_message_representative(
                            signaturePtr.baseAddress,
                            &self.key,
                            muPtr.baseAddress
                        )
                    }
                }

                guard rc == 1 else {
                    throw CryptoKitError.internalBoringSSLError()
                }

                return signature
            }
        }
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
extension MLDSA65.PublicKey {
    struct ExternalMuPublicKey: @unchecked Sendable {
        private var backing: Backing

        init(rawRepresentation: some DataProtocol) throws {
            self.backing = try Backing(rawRepresentation: rawRepresentation)
        }

        func prehash<D: DataProtocol>(for data: D) throws -> Data {
            let context: Data? = nil
            return try self.backing.prehash(for: data, context: context)
        }

        func prehash<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data {
            try self.backing.prehash(for: data, context: context)
        }

        fileprivate final class Backing {
            private var key: MLDSA65_public_key

            init(rawRepresentation: some DataProtocol) throws {
                guard rawRepresentation.count == Self.byteCount else {
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

            func prehash<D: DataProtocol, C: DataProtocol>(for data: D, context: C?) throws -> Data {
                var mu = Data(repeating: 0, count: MLDSA.muByteCount)

                let dataBytes: ContiguousBytes = data.regions.count == 1 ? data.regions.first! : Array(data)
                let rc: CInt = mu.withUnsafeMutableBytes { muPtr in
                    dataBytes.withUnsafeBytes { dataPtr in
                        context.withUnsafeBytes { contextPtr in
                            var prehash = MLDSA65_prehash()
                            let rc = CCryptoBoringSSL_MLDSA65_prehash_init(
                                &prehash,
                                &key,
                                contextPtr.baseAddress,
                                contextPtr.count
                            )
                            CCryptoBoringSSL_MLDSA65_prehash_update(&prehash, dataPtr.baseAddress, dataPtr.count)
                            CCryptoBoringSSL_MLDSA65_prehash_finalize(muPtr.baseAddress, &prehash)
                            return rc
                        }
                    }
                }

                guard rc == 1 else {
                    throw CryptoKitError.internalBoringSSLError()
                }

                return mu
            }

            static let byteCount = Int(MLDSA65_PUBLIC_KEY_BYTES)
        }
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
extension MLDSA87.PrivateKey {
    struct ExternalMuPrivateKey: @unchecked Sendable {
        private var backing: Backing

        init(seedRepresentation: some DataProtocol) throws {
            self.backing = try Backing(seedRepresentation: seedRepresentation)
        }

        func signature(forPrehashedMessageRepresentative mu: some DataProtocol) throws -> Data {
            try self.backing.signature(forPrehashedMessageRepresentative: mu)
        }

        fileprivate final class Backing {
            fileprivate var key: MLDSA87_private_key

            init(seedRepresentation: some DataProtocol) throws {
                guard seedRepresentation.count == MLDSA.seedByteCount else {
                    throw CryptoKitError.incorrectKeySize
                }

                self.key = .init()

                guard
                    Data(seedRepresentation).withUnsafeBytes({ seedPtr in
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

            func signature(forPrehashedMessageRepresentative mu: some DataProtocol) throws -> Data {
                guard mu.count == MLDSA.muByteCount else {
                    throw CryptoKitError.incorrectParameterSize
                }

                var signature = Data(repeating: 0, count: Int(MLDSA87_SIGNATURE_BYTES))

                let rc: CInt = signature.withUnsafeMutableBytes { signaturePtr in
                    let muBytes: ContiguousBytes = mu.regions.count == 1 ? mu.regions.first! : Array(mu)
                    return muBytes.withUnsafeBytes { muPtr in
                        CCryptoBoringSSL_MLDSA87_sign_message_representative(
                            signaturePtr.baseAddress,
                            &self.key,
                            muPtr.baseAddress
                        )
                    }
                }

                guard rc == 1 else {
                    throw CryptoKitError.internalBoringSSLError()
                }

                return signature
            }
        }
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
extension MLDSA87.PublicKey {
    struct ExternalMuPublicKey: @unchecked Sendable {
        private var backing: Backing

        init(rawRepresentation: some DataProtocol) throws {
            self.backing = try Backing(rawRepresentation: rawRepresentation)
        }

        func prehash<D: DataProtocol>(for data: D) throws -> Data {
            let context: Data? = nil
            return try self.backing.prehash(for: data, context: context)
        }

        func prehash<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data {
            try self.backing.prehash(for: data, context: context)
        }

        fileprivate final class Backing {
            private var key: MLDSA87_public_key

            init(rawRepresentation: some DataProtocol) throws {
                guard rawRepresentation.count == Self.byteCount else {
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

            func prehash<D: DataProtocol, C: DataProtocol>(for data: D, context: C?) throws -> Data {
                var mu = Data(repeating: 0, count: MLDSA.muByteCount)

                let dataBytes: ContiguousBytes = data.regions.count == 1 ? data.regions.first! : Array(data)
                let rc: CInt = mu.withUnsafeMutableBytes { muPtr in
                    dataBytes.withUnsafeBytes { dataPtr in
                        context.withUnsafeBytes { contextPtr in
                            var prehash = MLDSA87_prehash()
                            let rc = CCryptoBoringSSL_MLDSA87_prehash_init(
                                &prehash,
                                &key,
                                contextPtr.baseAddress,
                                contextPtr.count
                            )
                            CCryptoBoringSSL_MLDSA87_prehash_update(&prehash, dataPtr.baseAddress, dataPtr.count)
                            CCryptoBoringSSL_MLDSA87_prehash_finalize(muPtr.baseAddress, &prehash)
                            return rc
                        }
                    }
                }

                guard rc == 1 else {
                    throw CryptoKitError.internalBoringSSLError()
                }

                return mu
            }

            static let byteCount = Int(MLDSA87_PUBLIC_KEY_BYTES)
        }
    }
}

enum MLDSA {
    /// The size of the seed in bytes.
    static let seedByteCount = 32

    /// The size of the "mu" value in bytes.
    fileprivate static let muByteCount = 64
}

#endif
