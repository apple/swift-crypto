//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if canImport(CryptoKit)
@_exported import CryptoKit
#else
#if canImport(FoundationEssentials)
public import FoundationEssentials
#else
public import Foundation
#endif
// MARK: - Generated file, do NOT edit
// any edits of this file WILL be overwritten and thus discarded
// see section `gyb` in `README` for details.




// MARK: - AES.GCM + Nonce
extension AES.GCM {
    /// A value used once during a cryptographic operation and then discarded.
    ///
    /// Don’t reuse the same nonce for multiple calls to encryption APIs. It’s critical
    /// that nonces are unique per call to encryption APIs in order to protect the
    /// integrity of the encryption.
    public struct Nonce: ContiguousBytes, Sequence, Sendable {
        typealias Storage = ContiguousArray<UInt8>

        let storage: Storage

        /// Creates a new random nonce.
        ///
        /// The default nonce is a 12-byte random nonce.
        public init() {
            self.storage = Self.randomNonceStorage
        }

        /// Creates a nonce from the given data.
        ///
        /// Unless your use case calls for a nonce with a specific value, use the
        /// ``init()`` method to instead create a random nonce.
        ///
        /// - Parameters:
///   - data: A data representation of the nonce.
///     The initializer throws an error if the data has a length smaller than 12 bytes.
        internal init(data: RawSpan) throws(CryptoKitMetaError) {
            if data.byteCount < AES.GCM.defaultNonceByteCount {
                throw error(CryptoKitError.incorrectParameterSize)
            }

            self.storage = Storage(copying: data)
        }

        /// Creates a nonce from the given data.
        ///
        /// Unless your use case calls for a nonce with a specific value, use the
        /// ``init()`` method to instead create a random nonce.
        ///
        /// - Parameters:
///   - bytes: The bytes that represent the nonce.
///     The initializer throws an error if the data has a length smaller than 12 bytes.
        public init(copying bytes: RawSpan) throws(CryptoKitMetaError) {
            if bytes.byteCount < AES.GCM.defaultNonceByteCount {
                throw error(CryptoKitError.incorrectParameterSize)
            }

            self.storage = Storage(copying: bytes)
        }

        /// Creates a nonce from the given data.
        ///
        /// Unless your use case calls for a nonce with a specific value, use the
        /// ``init()`` method to instead create a random nonce.
        ///
        /// - Parameters:
///   - data: A data representation of the nonce.
///     The initializer throws an error if the data has a length smaller than 12 bytes.
        public init<D: DataProtocol>(data: D) throws(CryptoKitMetaError) {
            if data.count < AES.GCM.defaultNonceByteCount {
                throw error(CryptoKitError.incorrectParameterSize)
            }

            self.storage = Storage(data)
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
#if !hasFeature(Embedded)
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
#else
        public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
#endif

        /// The bytes stored in the nonce.
        public var bytes: RawSpan {
            get {
                storage.span.bytes
            }
        }

        /// The number of bytes stored in the nonce.
        public var count: Int { storage.count }

        /// Returns an iterator over the elements of the nonce.
        public func makeIterator() -> Array<UInt8>.Iterator {
            self.withUnsafeBytes({ (buffPtr) in
                return Array(buffPtr).makeIterator()
            })
        }

        /// Storage for a new, random nonce.
        static var randomNonceStorage: Storage {
            var data = Storage(repeating: 0, count: AES.GCM.defaultNonceByteCount)
            assert(data.count == AES.GCM.defaultNonceByteCount)

            var mutableSpan = data.mutableSpan
            var mutableBytes = mutableSpan.mutableBytes
            initializeRandomNonce(into: &mutableBytes)

            return data
        }

        /// Initialize the given mutable span with random bytes.
        static func initializeRandomNonce(into data: inout MutableRawSpan) {
            data.initializeWithRandomBytes(count: data.byteCount)
        }
    }
}

// MARK: - ChaChaPoly + Nonce
extension ChaChaPoly {
    /// A value used once during a cryptographic operation and then discarded.
    ///
    /// Don’t reuse the same nonce for multiple calls to encryption APIs. It’s critical
    /// that nonces are unique per call to encryption APIs in order to protect the
    /// integrity of the encryption.
    public struct Nonce: ContiguousBytes, Sequence, Sendable {
        typealias Storage = [12 of UInt8]

        let storage: Storage

        /// Creates a new random nonce.
        ///
        /// The default nonce is a 12-byte random nonce.
        public init() {
            self.storage = Self.randomNonceStorage
        }

        /// Creates a nonce from the given data.
        ///
        /// Unless your use case calls for a nonce with a specific value, use the
        /// ``init()`` method to instead create a random nonce.
        ///
        /// - Parameters:
///   - data: A 12-byte data representation of the nonce.
///     The initializer throws an error if the data isn't 12 bytes long.
        internal init(data: RawSpan) throws(CryptoKitMetaError) {
            if data.byteCount != ChaChaPoly.nonceByteCount {
                throw error(CryptoKitError.incorrectParameterSize)
            }

            self.storage = Storage(copying: data)
        }

        /// Creates a nonce from the given data.
        ///
        /// Unless your use case calls for a nonce with a specific value, use the
        /// ``init()`` method to instead create a random nonce.
        ///
        /// - Parameters:
///   - bytes: The bytes that represent the nonce.
///     The initializer throws an error if the data isn't 12 bytes long.
        public init(copying bytes: RawSpan) throws(CryptoKitMetaError) {
            if bytes.byteCount != ChaChaPoly.nonceByteCount {
                throw error(CryptoKitError.incorrectParameterSize)
            }

            self.storage = Storage(copying: bytes)
        }

        /// Creates a nonce from the given data.
        ///
        /// Unless your use case calls for a nonce with a specific value, use the
        /// ``init()`` method to instead create a random nonce.
        ///
        /// - Parameters:
///   - data: A 12-byte data representation of the nonce.
///     The initializer throws an error if the data isn't 12 bytes long.
        public init<D: DataProtocol>(data: D) throws(CryptoKitMetaError) {
            if data.count != ChaChaPoly.nonceByteCount {
                throw error(CryptoKitError.incorrectParameterSize)
            }

            self.storage = Storage(copying: data)
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
#if !hasFeature(Embedded)
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
#else
        public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
#endif

        /// The bytes stored in the nonce.
        public var bytes: RawSpan {
            get {
                storage.span.bytes
            }
        }

        /// The number of bytes stored in the nonce.
        public var count: Int { storage.count }

        /// Returns an iterator over the elements of the nonce.
        public func makeIterator() -> Array<UInt8>.Iterator {
            self.withUnsafeBytes({ (buffPtr) in
                return Array(buffPtr).makeIterator()
            })
        }

        /// Storage for a new, random nonce.
        static var randomNonceStorage: Storage {
            var data = Storage(repeating: 0)

            var mutableSpan = data.mutableSpan
            var mutableBytes = mutableSpan.mutableBytes
            initializeRandomNonce(into: &mutableBytes)

            return data
        }

        /// Initialize the given mutable span with random bytes.
        static func initializeRandomNonce(into data: inout MutableRawSpan) {
            data.initializeWithRandomBytes(count: data.byteCount)
        }
    }
}
#endif // canImport(CryptoKit)
