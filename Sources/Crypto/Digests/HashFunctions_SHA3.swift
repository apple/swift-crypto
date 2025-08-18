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
#if !CRYPTOKIT_IN_SEP
/// An implementation of Secure Hashing Algorithm 3 (SHA-3) hashing with a 256-bit digest.
///
/// The ``SHA3_256`` hash implements the ``HashFunction`` protocol for the
/// specific case of SHA-3 hashing with a 256-bit digest (``SHA3_256Digest``).
/// Larger digests take more space but are more secure.
///
/// Applications can compute the digest by calling the static ``hash(data:)``
/// method once. Alternatively, if the data to hash is too large to fit in memory,
/// applications can compute the digest iteratively by creating a new hash
/// instance, calling the ``update(data:)`` method repeatedly with blocks of
/// data, and then calling the ``finalize()`` method to get the result.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct SHA3_256: HashFunctionImplementationDetails, Sendable {
    /// The number of bytes that represents the hash function’s internal state.
    public static let blockByteCount: Int = 136
    /// The number of bytes in a SHA3-256 digest.
    public static let byteCount: Int = 32
    /// The digest type for a SHA3-256 hash function.
    public typealias Digest = SHA3_256Digest

    var impl: DigestImplSHA3<SHA3_256>

    /// Creates a SHA3-256 hash function.
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
        impl = DigestImplSHA3()
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

/// An implementation of Secure Hashing Algorithm 3 (SHA-3) hashing with a 384-bit digest.
///
/// The ``SHA3_384`` hash implements the ``HashFunction`` protocol for the
/// specific case of SHA-3 hashing with a 384-bit digest (``SHA3_384Digest``).
/// Larger digests take more space but are more secure.
///
/// Applications can compute the digest by calling the static ``hash(data:)``
/// method once. Alternatively, if the data to hash is too large to fit in memory,
/// applications can compute the digest iteratively by creating a new hash
/// instance, calling the ``update(data:)`` method repeatedly with blocks of
/// data, and then calling the ``finalize()`` method to get the result.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct SHA3_384: HashFunctionImplementationDetails, Sendable {
    /// The number of bytes that represents the hash function’s internal state.
    public static let blockByteCount: Int = 104
    /// The number of bytes in a SHA3-384 digest.
    public static let byteCount: Int = 48
    /// The digest type for a SHA3-384 hash function.
    public typealias Digest = SHA3_384Digest

    var impl: DigestImplSHA3<SHA3_384>

    /// Creates a SHA3-384 hash function.
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
        impl = DigestImplSHA3()
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

/// An implementation of Secure Hashing Algorithm 3 (SHA-3) hashing with a 512-bit digest.
///
/// The ``SHA3_512`` hash implements the ``HashFunction`` protocol for the
/// specific case of SHA-3 hashing with a 512-bit digest (``SHA3_512Digest``).
/// Larger digests take more space but are more secure.
///
/// Applications can compute the digest by calling the static ``hash(data:)``
/// method once. Alternatively, if the data to hash is too large to fit in memory,
/// applications can compute the digest iteratively by creating a new hash
/// instance, calling the ``update(data:)`` method repeatedly with blocks of
/// data, and then calling the ``finalize()`` method to get the result.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct SHA3_512: HashFunctionImplementationDetails, Sendable {
    /// The number of bytes that represents the hash function’s internal state.
    public static let blockByteCount: Int = 72
    /// The number of bytes in a SHA3-512 digest.
    public static let byteCount: Int = 64
    /// The digest type for a SHA3-512 hash function.
    public typealias Digest = SHA3_512Digest

    var impl: DigestImplSHA3<SHA3_512>

    /// Creates a SHA3-512 hash function.
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
        impl = DigestImplSHA3()
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
#endif // !CRYPTOKIT_IN_SEP
#endif // Linux or !SwiftPM
