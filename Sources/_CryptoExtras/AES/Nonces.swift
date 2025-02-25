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

fileprivate struct ByteIterator<T>: IteratorProtocol {
    var currentOffset = 0
    var iterator: Array<UInt8>.Iterator? = nil
    let length: Int
    
    init(_ bytes: T) {
        self.length = Mirror(reflecting: bytes).children.count
        withUnsafeBytes(of: bytes) { pointer in
            self.iterator = Array(pointer).makeIterator()
        }
    }
    
    @inlinable 
    public mutating func next() -> UInt8? {
        guard var iterator,
              currentOffset < length else { return nil }
        
        let next = iterator.next()
        currentOffset += 1
        return next
    }
}


// MARK: - AES._CBC + IV
extension AES._CBC {
    /// A value used once during a cryptographic operation and then discarded.
    ///
    /// Don’t reuse the same nonce for multiple calls to encryption APIs. It’s critical
    /// that nonces are unique per call to encryption APIs in order to protect the
    /// integrity of the encryption.
    public struct IV: Sendable, ContiguousBytes, Sequence {
        typealias IVTuple = (
            UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, 
            UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8
        )
    
        var bytes: IVTuple
        static var emptyBytes: IVTuple = (
            0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0
        )

        /// Creates a new random nonce.
        public init() {
            var bytes = Self.emptyBytes
            Swift.withUnsafeMutableBytes(of: &bytes) {
                let count = MemoryLayout<IVTuple>.size
                $0.initializeWithRandomBytes(count: count)
            }
            self.bytes = bytes
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
            guard [16].contains(ivBytes.count) else {
                throw CryptoKitError.incorrectKeySize
            }

            var bytes = Self.emptyBytes
            Swift.withUnsafeMutableBytes(of: &bytes) { bytesPtr in
                bytesPtr.copyBytes(from: ivBytes)
            }
            self.bytes = bytes
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
            guard [16].contains(data.count) else {
                throw CryptoKitError.incorrectKeySize
            }

            var bytes = Self.emptyBytes
            Swift.withUnsafeMutableBytes(of: &bytes) { bytesPtr in
                data.copyBytes(to: bytesPtr)
            }
            self.bytes = bytes
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
            var bytes = self.bytes
            return try Swift.withUnsafeBytes(of: &bytes, body)
        }
        
        mutating func withUnsafeMutableBytes<ReturnType>(_ body: (UnsafeMutableRawBufferPointer) throws -> ReturnType) rethrows -> ReturnType {
            var bytes = self.bytes
            return try Swift.withUnsafeMutableBytes(of: &bytes, body)
        }
        
        /// Returns an iterator over the elements of the nonce.
        public func makeIterator() -> some IteratorProtocol<UInt8> {
            ByteIterator(bytes)
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
        typealias IVTuple = (UInt64, UInt64)
    
        var bytes: IVTuple
        static var emptyBytes: IVTuple = (0, 0)

        /// Creates a new random nonce.
        public init() {
            var bytes = Self.emptyBytes
            Swift.withUnsafeMutableBytes(of: &bytes) {
                let count = MemoryLayout<IVTuple>.size
                $0.initializeWithRandomBytes(count: count)
            }
            self.bytes = bytes
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
            guard [16].contains(ivBytes.count) else {
                throw CryptoKitError.incorrectKeySize
            }

            var bytes = Self.emptyBytes
            Swift.withUnsafeMutableBytes(of: &bytes) { bytesPtr in
                bytesPtr.copyBytes(from: ivBytes)
            }
            self.bytes = bytes
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
            guard [16].contains(data.count) else {
                throw CryptoKitError.incorrectKeySize
            }

            var bytes = Self.emptyBytes
            Swift.withUnsafeMutableBytes(of: &bytes) { bytesPtr in
                data.copyBytes(to: bytesPtr)
            }
            self.bytes = bytes
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
            var bytes = self.bytes
            return try Swift.withUnsafeBytes(of: &bytes, body)
        }
        
        mutating func withUnsafeMutableBytes<ReturnType>(_ body: (UnsafeMutableRawBufferPointer) throws -> ReturnType) rethrows -> ReturnType {
            var bytes = self.bytes
            return try Swift.withUnsafeMutableBytes(of: &bytes, body)
        }
        
        /// Returns an iterator over the elements of the nonce.
        public func makeIterator() -> some IteratorProtocol<UInt8> {
            ByteIterator(bytes)
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
        typealias NonceTuple = (UInt64, UInt32, UInt32)
    
        var bytes: NonceTuple
        static var emptyBytes: NonceTuple = (0, 0, 0)

        /// Creates a new random nonce.
        public init() {
            var bytes = Self.emptyBytes
            Swift.withUnsafeMutableBytes(of: &bytes) {
                let count = MemoryLayout<NonceTuple>.size
                $0.initializeWithRandomBytes(count: count)
            }
            self.bytes = bytes
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
            guard [12, 16].contains(nonceBytes.count) else {
                throw CryptoKitError.incorrectKeySize
            }

            var bytes = Self.emptyBytes
            Swift.withUnsafeMutableBytes(of: &bytes) { bytesPtr in
                bytesPtr.copyBytes(from: nonceBytes)
            }
            self.bytes = bytes
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
            guard [12, 16].contains(data.count) else {
                throw CryptoKitError.incorrectKeySize
            }

            var bytes = Self.emptyBytes
            Swift.withUnsafeMutableBytes(of: &bytes) { bytesPtr in
                data.copyBytes(to: bytesPtr)
            }
            self.bytes = bytes
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
            var bytes = self.bytes
            return try Swift.withUnsafeBytes(of: &bytes, body)
        }
        
        mutating func withUnsafeMutableBytes<ReturnType>(_ body: (UnsafeMutableRawBufferPointer) throws -> ReturnType) rethrows -> ReturnType {
            var bytes = self.bytes
            return try Swift.withUnsafeMutableBytes(of: &bytes, body)
        }
        
        /// Returns an iterator over the elements of the nonce.
        public func makeIterator() -> some IteratorProtocol<UInt8> {
            ByteIterator(bytes)
        }
    }
}
