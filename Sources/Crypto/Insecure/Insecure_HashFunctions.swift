//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
extension Insecure {
    /// An implementation of SHA1 hashing.
    ///
    /// The ``SHA1`` hash implements the ``HashFunction`` protocol to produce a
    /// SHA1 digest (``SHA1Digest``).
    ///
    /// You can compute the digest by calling the static ``hash(data:)`` method
    /// once. Alternatively, if the data that you want to hash is too large to
    /// fit in memory, you can compute the digest iteratively by creating a new
    /// hash instance, calling the ``update(data:)`` method repeatedly with
    /// blocks of data, and then calling the ``finalize()`` method to get the
    /// result.
    ///
    /// - Important: This hash algorithm isn’t considered cryptographically
    /// secure, but is provided for backward compatibility with older services
    /// that require it. For new services, prefer one of the secure hashes, like
    /// ``SHA512``.
    public struct SHA1: HashFunctionImplementationDetails {
        /// The number of bytes that represents the hash function’s internal
        /// state.
        public static var blockByteCount: Int {
            get { 64 }
            
            set { fatalError("Cannot set SHA1.blockByteCount") }
        }
        
        /// The number of bytes in a SHA1 digest.
        public static var byteCount: Int {
            get { 20 }
            
            set { fatalError("Cannot set SHA1.byteCount") }
        }
        
        /// The digest type for a SHA1 hash function.
        public typealias Digest = Insecure.SHA1Digest
        var impl: DigestImpl<SHA1>

        /// Creates a SHA1 hash function.
        ///
        /// Initialize a new hash function by calling this method if you want to
        /// hash the data iteratively, such as when you don’t have a buffer
        /// large enough to hold all the data at once. Provide data blocks to
        /// the hash function using the ``update(data:)`` or
        /// ``update(bufferPointer:)`` method. After providing all the data,
        /// call ``finalize()`` to get the digest.
        ///
        /// If your data fits into a single buffer, you can use the
        /// ``hash(data:)`` method instead, to compute the digest in a single
        /// call.
        public init() {
            impl = DigestImpl()
        }

        /// Incrementally updates the hash function with the contents of the
        /// buffer.
        ///
        /// Call this method one or more times to provide data to the hash
        /// function in blocks. After providing the last block of data, call the
        /// ``finalize()`` method to get the computed digest. Don’t call the
        /// update method again after finalizing the hash function.
        ///
        /// - Note: Typically, it’s safer to use an instance of
        /// <doc://com.apple.documentation/documentation/foundation/data>, or
        /// some other type that conforms to the
        /// <doc://com.apple.documentation/documentation/foundation/dataprotocol>,
        /// to hold your data. When possible, use the ``update(data:)`` method
        /// instead.
        ///
        /// - Parameters:
        ///   - bufferPointer: A pointer to the next block of data for the ongoing
        /// digest calculation.
        public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
            impl.update(data: bufferPointer)
        }

        /// Finalizes the hash function and returns the computed digest.
        ///
        /// Call this method after you provide the hash function with all the
        /// data to hash by making one or more calls to the ``update(data:)`` or
        /// ``update(bufferPointer:)`` method. After finalizing the hash
        /// function, discard it. To compute a new digest, create a new hash
        /// function with a call to the ``init()`` method.
        ///
        /// - Returns: The computed digest of the data.
        public func finalize() -> Self.Digest {
            return impl.finalize()
        }
    }

    /// An implementation of MD5 hashing.
    ///
    /// The ``MD5`` hash implements the ``HashFunction`` protocol to produce an
    /// MD5 digest (``MD5Digest``).
    ///
    /// You can compute the digest by calling the static ``hash(data:)`` method
    /// once. Alternatively, if the data that you want to hash is too large to
    /// fit in memory, you can compute the digest iteratively by creating a new
    /// hash instance, calling the ``update(data:)`` method repeatedly with
    /// blocks of data, and then calling the ``finalize()`` method to get the
    /// result.
    ///
    /// - Important: This hash algorithm isn’t considered cryptographically
    /// secure, but is provided for backward compatibility with older services
    /// that require it. For new services, prefer one of the secure hashes, like
    /// ``SHA512``.
    public struct MD5: HashFunctionImplementationDetails {
        /// The number of bytes that represents the hash function’s internal
        /// state.
        public static var blockByteCount: Int {
            get { 64 }
            
            set { fatalError("Cannot set MD5.blockByteCount") }
        }
        /// The number of bytes in an MD5 digest.
        public static var byteCount: Int {
            get { 16 }
            
            set { fatalError("Cannot set MD5.byteCount") }
        }
        
        /// The digest type for a MD5 hash function.
        public typealias Digest = Insecure.MD5Digest
        var impl: DigestImpl<MD5>

        /// Creates a MD5 hash function.
        ///
        /// Initialize a new hash function by calling this method if you want to
        /// hash the data iteratively, such as when you don’t have a buffer
        /// large enough to hold all the data at once. Provide data blocks to
        /// the hash function using the ``update(data:)`` or
        /// ``update(bufferPointer:)`` method. After providing all the data,
        /// call ``finalize()`` to get the digest.
        ///
        /// If your data fits into a single buffer, you can use the
        /// ``hash(data:)`` method instead, to compute the digest in a single
        /// call.
        public init() {
            impl = DigestImpl()
        }

        /// Incrementally updates the hash function with the contents of the
        /// buffer.
        ///
        /// Call this method one or more times to provide data to the hash
        /// function in blocks. After providing the last block of data, call the
        /// ``finalize()`` method to get the computed digest. Don’t call the
        /// update method again after finalizing the hash function.
        ///
        /// - Note: Typically, it’s safer to use an instance of
        /// <doc://com.apple.documentation/documentation/foundation/data>, or
        /// some other type that conforms to the
        /// <doc://com.apple.documentation/documentation/foundation/dataprotocol>,
        /// to hold your data. When possible, use the ``update(data:)`` method
        /// instead.
        ///
        /// - Parameters:
        ///   - bufferPointer: A pointer to the next block of data for the ongoing
        /// digest calculation.
        public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
            impl.update(data: bufferPointer)
        }

        /// Finalizes the hash function and returns the computed digest.
        ///
        /// Call this method after you provide the hash function with all the
        /// data to hash by making one or more calls to the ``update(data:)`` or
        /// ``update(bufferPointer:)`` method. After finalizing the hash
        /// function, discard it. To compute a new digest, create a new hash
        /// function with a call to the ``init()`` method.
        ///
        /// - Returns: The computed digest of the data.
        public func finalize() -> Self.Digest {
            return impl.finalize()
        }
    }
}
#endif  // Linux or !SwiftPM
