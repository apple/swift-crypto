//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims
import Crypto
import CryptoBoringWrapper
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias ChaCha20CTRImpl = OpenSSLChaCha20CTRImpl

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Insecure {
    /// ChaCha20-CTR with 96-bit nonces and a 32 bit counter.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum ChaCha20CTR {
        static let keyBitsCount = 256
        static let nonceByteCount = 12
        static let counterByteCount = 4

        /// Encrypts data using ChaCha20CTR
        ///
        /// - Parameters:
        ///   - message: The message to encrypt
        ///   - key: A 256-bit encryption key
        ///   - counter: A 4 byte counter (UInt32), defaults to 0
        ///   - nonce: A 12 byte nonce for ChaCha20 encryption. The nonce must be unique for every use of the key to seal data.
        /// - Returns: The encrypted ciphertext
        /// - Throws: CipherError errors
        /// - Warning: You most likely want to use the ChaChaPoly implementation with AuthenticatedData available at `Crypto.ChaChaPoly`
        public static func encrypt<
            Plaintext: DataProtocol
        >(
            _ message: Plaintext,
            using key: SymmetricKey,
            counter: Insecure.ChaCha20CTR.Counter = Counter(),
            nonce: Insecure.ChaCha20CTR.Nonce
        ) throws -> Data {
            return try ChaCha20CTRImpl.encrypt(key: key, message: message, counter: counter.counter, nonce: nonce.bytes)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Insecure.ChaCha20CTR {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public struct Nonce: Sendable, ContiguousBytes, Sequence {
        let bytes: Data

        /// Generates a fresh random Nonce. Unless required by a specification to provide a specific Nonce, this is the recommended initializer.
        public init() {
            var data = Data(repeating: 0, count: Insecure.ChaCha20CTR.nonceByteCount)
            data.withUnsafeMutableBytes {
                assert($0.count == Insecure.ChaCha20CTR.nonceByteCount)
                $0.initializeWithRandomBytes(count: Insecure.ChaCha20CTR.nonceByteCount)
            }
            self.bytes = data
        }

        public init<D: DataProtocol>(data: D) throws {
            if data.count != Insecure.ChaCha20CTR.nonceByteCount {
                throw CryptoKitError.incorrectParameterSize
            }

            self.bytes = Data(data)
        }

        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }

        public func makeIterator() -> Array<UInt8>.Iterator {
            self.withUnsafeBytes({ buffPtr in
                Array(buffPtr).makeIterator()
            })
        }
    }

    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public struct Counter: Sendable, ContiguousBytes {
        let counter: UInt32

        /// Generates a fresh Counter set to 0. Unless required by a specification to provide a specific Counter, this is the recommended initializer.
        public init() {
            self.counter = 0
        }

        /// Explicitly set the Counter's offset using a byte sequence
        public init<D: DataProtocol>(data: D) throws {
            if data.count != Insecure.ChaCha20CTR.counterByteCount {
                throw CryptoKitError.incorrectParameterSize
            }

            let startIndex = data.startIndex
            self.counter = (
                (UInt32(data[data.index(startIndex, offsetBy: 0)]) << 0) |
                (UInt32(data[data.index(startIndex, offsetBy: 1)]) << 8) |
                (UInt32(data[data.index(startIndex, offsetBy: 2)]) << 16) |
                (UInt32(data[data.index(startIndex, offsetBy: 3)]) << 24)
            )
        }

        /// Explicitly set the Counter's offset using a UInt32
        public init(offset: UInt32) throws {
            self.counter = offset
        }

        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try Swift.withUnsafeBytes(of: self.counter, body)
        }
    }
}
