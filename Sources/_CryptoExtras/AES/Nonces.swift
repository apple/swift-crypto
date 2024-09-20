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
import Foundation
// MARK: - Generated file, do NOT edit
// any edits of this file WILL be overwritten and thus discarded
// see section `gyb` in `README` for details.

// MARK: - AES._CBC + IV
extension AES._CBC {
    /// A value used once during a cryptographic operation and then discarded.
    ///
    /// Don’t reuse the same nonce for multiple calls to encryption APIs. It’s critical
    /// that nonces are unique per call to encryption APIs in order to protect the
    /// integrity of the encryption.
    public struct IV: Sendable, ContiguousBytes, Sequence {
        private var bytes: Data

        /// Creates a new random nonce.
        public init() {
            var data = Data(repeating: 0, count: AES._CBC.nonceByteCount)
            data.withUnsafeMutableBytes {
                assert($0.count == AES._CBC.nonceByteCount)
                $0.initializeWithRandomBytes(count: AES._CBC.nonceByteCount)
            }
            self.bytes = data
        }
        
        /// Creates a nonce from the given collection.
        ///
        /// Unless your use case calls for a nonce with a specific value, use the
        /// ``init()`` method to instead create a random nonce.
        ///
        /// - Parameters:
        ///   - ivBytes: A collection of bytes representation of the nonce. 
        /// The initializer throws an error if the data has the incorrect length.
        public init<IVBytes: Collection>(ivBytes: IVBytes) throws where IVBytes.Element == UInt8 {
            guard ivBytes.count == AES._CBC.nonceByteCount else {
                throw CryptoKitError.incorrectKeySize
            }

            self.bytes = Data(repeating: 0, count: AES._CBC.nonceByteCount)
            Swift.withUnsafeMutableBytes(of: &self.bytes) { bytesPtr in
                bytesPtr.copyBytes(from: ivBytes)
            }
        }
        
        /// Creates a nonce from the given data.
        ///
        /// Unless your use case calls for a nonce with a specific value, use the
        /// ``init()`` method to instead create a random nonce.
        ///
        /// - Parameters:
        ///   - data: A data representation of the nonce. The initializer throws an
        /// error if the data has the incorrect length.
        public init<D: DataProtocol>(data: D) throws {
            if data.count != AES._CBC.nonceByteCount {
                throw CryptoKitError.incorrectParameterSize
            }

            self.bytes = Data(data)
        }
        
        /// Calls the given closure with a pointer to the underlying bytes of the array’s
        /// contiguous storage.
        ///
        /// - Parameters:
        ///   - body: A closure with an `UnsafeRawBufferPointer` parameter that points to the
        /// contiguous storage for the array. The system creates the storage if it doesn’t
        /// exist. If body has a return value, that value is also used as the return value
        /// for the ``withUnsafeBytes(_:)`` method. The argument is valid only for
        /// the duration of the closure’s execution.
        ///
        /// - Returns: The return value, if any, of the body closure parameter.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
        
        mutating func withUnsafeMutableBytes<ReturnType>(_ body: (UnsafeMutableRawBufferPointer) throws -> ReturnType) rethrows -> ReturnType {
            return try Swift.withUnsafeMutableBytes(of: &self.bytes, body)
        }
        
        /// Returns an iterator over the elements of the nonce.
        public func makeIterator() -> Array<UInt8>.Iterator {
            self.withUnsafeBytes({ (buffPtr) in
                return Array(buffPtr).makeIterator()
            })
        }
    }
}

// MARK: - AES._CFB + IV
extension AES._CFB {
    /// A value used once during a cryptographic operation and then discarded.
    ///
    /// Don’t reuse the same nonce for multiple calls to encryption APIs. It’s critical
    /// that nonces are unique per call to encryption APIs in order to protect the
    /// integrity of the encryption.
    public struct IV: Sendable, ContiguousBytes, Sequence {
        private var bytes: Data

        /// Creates a new random nonce.
        public init() {
            var data = Data(repeating: 0, count: AES._CFB.nonceByteCount)
            data.withUnsafeMutableBytes {
                assert($0.count == AES._CFB.nonceByteCount)
                $0.initializeWithRandomBytes(count: AES._CFB.nonceByteCount)
            }
            self.bytes = data
        }
        
        /// Creates a nonce from the given collection.
        ///
        /// Unless your use case calls for a nonce with a specific value, use the
        /// ``init()`` method to instead create a random nonce.
        ///
        /// - Parameters:
        ///   - ivBytes: A collection of bytes representation of the nonce. 
        /// The initializer throws an error if the data has the incorrect length.
        public init<IVBytes: Collection>(ivBytes: IVBytes) throws where IVBytes.Element == UInt8 {
            guard ivBytes.count == AES._CFB.nonceByteCount else {
                throw CryptoKitError.incorrectKeySize
            }

            self.bytes = Data(repeating: 0, count: AES._CFB.nonceByteCount)
            Swift.withUnsafeMutableBytes(of: &self.bytes) { bytesPtr in
                bytesPtr.copyBytes(from: ivBytes)
            }
        }
        
        /// Creates a nonce from the given data.
        ///
        /// Unless your use case calls for a nonce with a specific value, use the
        /// ``init()`` method to instead create a random nonce.
        ///
        /// - Parameters:
        ///   - data: A data representation of the nonce. The initializer throws an
        /// error if the data has the incorrect length.
        public init<D: DataProtocol>(data: D) throws {
            if data.count != AES._CFB.nonceByteCount {
                throw CryptoKitError.incorrectParameterSize
            }

            self.bytes = Data(data)
        }
        
        /// Calls the given closure with a pointer to the underlying bytes of the array’s
        /// contiguous storage.
        ///
        /// - Parameters:
        ///   - body: A closure with an `UnsafeRawBufferPointer` parameter that points to the
        /// contiguous storage for the array. The system creates the storage if it doesn’t
        /// exist. If body has a return value, that value is also used as the return value
        /// for the ``withUnsafeBytes(_:)`` method. The argument is valid only for
        /// the duration of the closure’s execution.
        ///
        /// - Returns: The return value, if any, of the body closure parameter.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
        
        mutating func withUnsafeMutableBytes<ReturnType>(_ body: (UnsafeMutableRawBufferPointer) throws -> ReturnType) rethrows -> ReturnType {
            return try Swift.withUnsafeMutableBytes(of: &self.bytes, body)
        }
        
        /// Returns an iterator over the elements of the nonce.
        public func makeIterator() -> Array<UInt8>.Iterator {
            self.withUnsafeBytes({ (buffPtr) in
                return Array(buffPtr).makeIterator()
            })
        }
    }
}

// MARK: - AES._CTR + Nonce
extension AES._CTR {
    /// A value used once during a cryptographic operation and then discarded.
    ///
    /// Don’t reuse the same nonce for multiple calls to encryption APIs. It’s critical
    /// that nonces are unique per call to encryption APIs in order to protect the
    /// integrity of the encryption.
    public struct Nonce: Sendable, ContiguousBytes, Sequence {
        private var bytes: Data

        /// Creates a new random nonce.
        public init() {
            var data = Data(repeating: 0, count: AES._CTR.nonceByteCount)
            data.withUnsafeMutableBytes {
                assert($0.count == AES._CTR.nonceByteCount)
                $0.initializeWithRandomBytes(count: AES._CTR.nonceByteCount)
            }
            self.bytes = data
        }
        
        /// Creates a nonce from the given collection.
        ///
        /// Unless your use case calls for a nonce with a specific value, use the
        /// ``init()`` method to instead create a random nonce.
        ///
        /// - Parameters:
        ///   - nonceBytes: A collection of bytes representation of the nonce. 
        /// The initializer throws an error if the data has the incorrect length.
        public init<NonceBytes: Collection>(nonceBytes: NonceBytes) throws where NonceBytes.Element == UInt8 {
            guard nonceBytes.count == AES._CTR.nonceByteCount else {
                throw CryptoKitError.incorrectKeySize
            }

            self.bytes = Data(repeating: 0, count: AES._CTR.nonceByteCount)
            Swift.withUnsafeMutableBytes(of: &self.bytes) { bytesPtr in
                bytesPtr.copyBytes(from: nonceBytes)
            }
        }
        
        /// Creates a nonce from the given data.
        ///
        /// Unless your use case calls for a nonce with a specific value, use the
        /// ``init()`` method to instead create a random nonce.
        ///
        /// - Parameters:
        ///   - data: A data representation of the nonce. The initializer throws an
        /// error if the data has the incorrect length.
        public init<D: DataProtocol>(data: D) throws {
            if data.count != AES._CBC.nonceByteCount {
                throw CryptoKitError.incorrectParameterSize
            }

            self.bytes = Data(data)
        }
        
        /// Calls the given closure with a pointer to the underlying bytes of the array’s
        /// contiguous storage.
        ///
        /// - Parameters:
        ///   - body: A closure with an `UnsafeRawBufferPointer` parameter that points to the
        /// contiguous storage for the array. The system creates the storage if it doesn’t
        /// exist. If body has a return value, that value is also used as the return value
        /// for the ``withUnsafeBytes(_:)`` method. The argument is valid only for
        /// the duration of the closure’s execution.
        ///
        /// - Returns: The return value, if any, of the body closure parameter.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
        
        mutating func withUnsafeMutableBytes<ReturnType>(_ body: (UnsafeMutableRawBufferPointer) throws -> ReturnType) rethrows -> ReturnType {
            return try Swift.withUnsafeMutableBytes(of: &self.bytes, body)
        }
        
        /// Returns an iterator over the elements of the nonce.
        public func makeIterator() -> Array<UInt8>.Iterator {
            self.withUnsafeBytes({ (buffPtr) in
                return Array(buffPtr).makeIterator()
            })
        }
    }
}
