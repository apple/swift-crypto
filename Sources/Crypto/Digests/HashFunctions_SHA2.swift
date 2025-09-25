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
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
/// An implementation of Secure Hashing Algorithm 2 (SHA-2) hashing with a
/// 256-bit digest.
///
/// The ``SHA2_256`` hash implements the ``HashFunction`` protocol for the
/// specific case of SHA-2 hashing with a 256-bit digest (``SHA256Digest``).
/// Larger digests take more space but are more secure.
///
/// You can compute the digest by calling the static ``hash(data:)`` method
/// once. Alternatively, if the data that you want to hash is too large to fit
/// in memory, you can compute the digest iteratively by creating a new hash
/// instance, calling the ``update(data:)`` method repeatedly with blocks of
/// data, and then calling the ``finalize()`` method to get the result.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public typealias SHA2_256 = SHA256

/// An implementation of Secure Hashing Algorithm 2 (SHA-2) hashing with a
/// 256-bit digest.
///
/// The ``SHA256`` hash implements the ``HashFunction`` protocol for the
/// specific case of SHA-2 hashing with a 256-bit digest (``SHA256Digest``).
/// Larger digests take more space but are more secure.
///
/// You can compute the digest by calling the static ``hash(data:)`` method
/// once. Alternatively, if the data that you want to hash is too large to fit
/// in memory, you can compute the digest iteratively by creating a new hash
/// instance, calling the ``update(data:)`` method repeatedly with blocks of
/// data, and then calling the ``finalize()`` method to get the result.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct SHA256: HashFunctionImplementationDetails, Sendable {
    /// The number of bytes that represents the hash function’s internal state.
    public static let blockByteCount: Int = 64
    /// The number of bytes in a SHA256 digest.
    public static let byteCount: Int = 32
    /// The digest type for a SHA256 hash function.
    public typealias Digest = SHA256Digest
    
    var impl: DigestImpl<SHA256>

    /// Creates a SHA256 hash function.
    ///
    /// Initialize a new hash function by calling this method if you want to
    /// hash data iteratively, such as when you don’t have a buffer large enough
    /// to hold all the data at once. Provide data blocks to the hash function
    /// using the ``update(data:)`` or ``update(bufferPointer:)`` method. After
    /// providing all the data, call ``finalize()`` to get the digest.
    ///
    /// If your data fits into a single buffer, you can use the ``hash(data:)``
    /// method instead, to compute the digest in a single call.
    public init() {
        impl = DigestImpl()
    }

    /// Incrementally updates the hash function with the contents of the buffer.
    ///
    /// Call this method one or more times to provide data to the hash function
    /// in blocks. After providing the last block of data, call the
    /// ``finalize()`` method to get the computed digest. Don’t call the update
    /// method again after finalizing the hash function.
    ///
    /// - Note: Typically, it’s safer to use an instance of
    /// <doc://com.apple.documentation/documentation/foundation/data>, or some
    /// other type that conforms to the
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
    /// Call this method after you provide the hash function with all the data
    /// to hash by making one or more calls to the ``update(data:)`` or
    /// ``update(bufferPointer:)`` method. After finalizing the hash function,
    /// discard it. To compute a new digest, create a new hash function with a
    /// call to the ``init()`` method.
    ///
    /// - Returns: The computed digest of the data.
    public func finalize() -> Self.Digest {
        return impl.finalize()
    }
}

/// An implementation of Secure Hashing Algorithm 2 (SHA-2) hashing with a
/// 384-bit digest.
///
/// The ``SHA2_384`` hash implements the ``HashFunction`` protocol for the
/// specific case of SHA-2 hashing with a 384-bit digest (``SHA384Digest``).
/// Larger digests take more space but are more secure.
///
/// You can compute the digest by calling the static ``hash(data:)`` method
/// once. Alternatively, if the data that you want to hash is too large to fit
/// in memory, you can compute the digest iteratively by creating a new hash
/// instance, calling the ``update(data:)`` method repeatedly with blocks of
/// data, and then calling the ``finalize()`` method to get the result.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public typealias SHA2_384 = SHA384

/// An implementation of Secure Hashing Algorithm 2 (SHA-2) hashing with a
/// 384-bit digest.
///
/// The ``SHA384`` hash implements the ``HashFunction`` protocol for the
/// specific case of SHA-2 hashing with a 384-bit digest (``SHA384Digest``).
/// Larger digests take more space but are more secure.
///
/// You can compute the digest by calling the static ``hash(data:)`` method
/// once. Alternatively, if the data that you want to hash is too large to fit
/// in memory, you can compute the digest iteratively by creating a new hash
/// instance, calling the ``update(data:)`` method repeatedly with blocks of
/// data, and then calling the ``finalize()`` method to get the result.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct SHA384: HashFunctionImplementationDetails, Sendable {
    /// The number of bytes that represents the hash function’s internal state.
    public static let blockByteCount: Int = 128
    /// The number of bytes in a SHA384 digest.
    public static let byteCount: Int = 48
    
    /// The digest type for a SHA384 hash function.
    public typealias Digest = SHA384Digest
    var impl: DigestImpl<SHA384>

    /// Creates a SHA384 hash function.
    ///
    /// Initialize a new hash function by calling this method if you want to
    /// hash the data iteratively, such as when you don’t have a buffer large
    /// enough to hold all the data at once. Provide data blocks to the hash
    /// function using the ``update(data:)`` or ``update(bufferPointer:)``
    /// method. After providing all the data, call ``finalize()`` to get the
    /// digest.
    ///
    /// If your data fits into a single buffer, you can use the ``hash(data:)``
    /// method instead, to compute the digest in a single call.
    public init() {
        impl = DigestImpl()
    }

    /// Incrementally updates the hash function with the contents of the buffer.
    ///
    /// Call this method one or more times to provide data to the hash function
    /// in blocks. After providing the last block of data, call the
    /// ``finalize()`` method to get the computed digest. Don’t call the update
    /// method again after finalizing the hash function.
    ///
    /// - Note: Typically, it’s safer to use an instance of
    /// <doc://com.apple.documentation/documentation/foundation/data>, or some
    /// other type that conforms to the
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
    /// Call this method after you provide the hash function with all the data
    /// to hash by making one or more calls to the ``update(data:)`` or
    /// ``update(bufferPointer:)`` method. After finalizing the hash function,
    /// discard it. To compute a new digest, create a new hash function with a
    /// call to the ``init()`` method.
    ///
    /// - Returns: The computed digest of the data.
    public func finalize() -> Self.Digest {
        return impl.finalize()
    }
}

/// An implementation of Secure Hashing Algorithm 2 (SHA-2) hashing with a
/// 512-bit digest.
///
/// The ``SHA2_512`` hash implements the ``HashFunction`` protocol for the
/// specific case of SHA-2 hashing with a 512-bit digest (``SHA512Digest``).
/// Larger digests take more space but are more secure.
///
/// You can compute the digest by calling the static ``hash(data:)`` method
/// once. Alternatively, if the data that you want to hash is too large to fit
/// in memory, you can compute the digest iteratively by creating a new hash
/// instance, calling the ``update(data:)`` method repeatedly with blocks of
/// data, and then calling the ``finalize()`` method to get the result.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public typealias SHA2_512 = SHA512

/// An implementation of Secure Hashing Algorithm 2 (SHA-2) hashing with a
/// 512-bit digest.
///
/// The ``SHA512`` hash implements the ``HashFunction`` protocol for the
/// specific case of SHA-2 hashing with a 512-bit digest (``SHA512Digest``).
/// Larger digests take more space but are more secure.
///
/// You can compute the digest by calling the static ``hash(data:)`` method
/// once. Alternatively, if the data that you want to hash is too large to fit
/// in memory, you can compute the digest iteratively by creating a new hash
/// instance, calling the ``update(data:)`` method repeatedly with blocks of
/// data, and then calling the ``finalize()`` method to get the result.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct SHA512: HashFunctionImplementationDetails, Sendable {
    /// The number of bytes that represents the hash function’s internal state.
    public static let blockByteCount: Int = 128
    /// The number of bytes in a SHA512 digest.
    public static let byteCount: Int = 64
    /// The digest type for a SHA512 hash function.
    public typealias Digest = SHA512Digest
    
    var impl: DigestImpl<SHA512>

    /// Creates a SHA512 hash function.
    ///
    /// Initialize a new hash function by calling this method if you want to
    /// hash the data iteratively, such as when you don’t have a buffer large
    /// enough to hold all the data at once. Provide data blocks to the hash
    /// function using the ``update(data:)`` or ``update(bufferPointer:)``
    /// method. After providing all the data, call ``finalize()`` to get the
    /// digest.
    ///
    /// If your data fits into a single buffer, you can use the ``hash(data:)``
    /// method instead, to compute the digest in a single call.
    public init() {
        impl = DigestImpl()
    }

    /// Incrementally updates the hash function with the contents of the buffer.
    ///
    /// Call this method one or more times to provide data to the hash function
    /// in blocks. After providing the last block of data, call the
    /// ``finalize()`` method to get the computed digest. Don’t call the update
    /// method again after finalizing the hash function.
    ///
    /// - Note: Typically, it’s safer to use an instance of
    /// <doc://com.apple.documentation/documentation/foundation/data>, or some
    /// other type that conforms to the
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
    /// Call this method after you provide the hash function with all the data
    /// to hash by making one or more calls to the ``update(data:)`` or
    /// ``update(bufferPointer:)`` method. After finalizing the hash function,
    /// discard it. To compute a new digest, create a new hash function with a
    /// call to the ``init()`` method.
    ///
    /// - Returns: The computed digest of the data.
    public func finalize() -> Self.Digest {
        return impl.finalize()
    }
}
#endif // Linux or !SwiftPM
