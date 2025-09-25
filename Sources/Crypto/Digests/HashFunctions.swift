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
#if (!CRYPTO_IN_SWIFTPM_FORCE_BUILD_API) || CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias DigestImpl = CoreCryptoDigestImpl
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias DigestImplSHA3 = CoreCryptoDigestImpl
#else
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias DigestImpl = OpenSSLDigestImpl
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias DigestImplSHA3 = XKCPDigestImpl
#endif

#if CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
public import SwiftSystem
#else
#if canImport(FoundationEssentials)
public import FoundationEssentials
#else
public import Foundation
#endif
#endif

/// A type that performs cryptographically secure hashing.
///
/// The ``HashFunction`` protocol describes an interface for computing a
/// fixed-length digest from an arbitrarily large collection of bytes. Because
/// the digest is small, you can quickly compare the digests to detect a
/// difference in two corresponding data sets. Alternatively, transmit or store
/// data with its digest to detect changes introduced after initially
/// calculating the digest.
///
/// Use one of the protocol’s adopters, like ``SHA256``, ``SHA384``, or
/// ``SHA512``, to output a digest whose value varies significantly over even
/// small differences in the input data.
///
/// Checking a digest doesn’t guard against changes made by a malicious user who
/// also changes the digest to match. To handle this, compute a message
/// authentication code (MAC) like ``HMAC`` instead. MACs rely on hashing, but
/// incorporate a secret cryptographic key into the digest computation. Only a
/// user that has the key can generate a valid MAC.
@preconcurrency
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public protocol HashFunction: Sendable {
    /// The number of bytes that represents the hash function’s internal state.
    static var blockByteCount: Int { get }
    #if (!CRYPTO_IN_SWIFTPM_FORCE_BUILD_API) || CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
    /// The type of the digest returned by the hash function.
    associatedtype Digest: CryptoKit.Digest
    #else
    associatedtype Digest: Crypto.Digest
    #endif

    /// Creates a hash function.
    ///
    /// Initialize a new hash function by calling this method if you want to
    /// hash the data iteratively, such as when you don’t have a buffer large
    /// enough to hold all the data at once. Provide data blocks to the hash
    /// function using the ``update(data:)`` or ``update(bufferPointer:)``
    /// method. After providing all the data, call ``finalize()`` to get the
    /// digest.
    ///
    /// If your data fits into a single buffer, you can use the ``hash(data:)``
    /// method instead to compute the digest in a single call.
    init()

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
    /// to hold your data. When possible, use the ``HashFunction/update(data:)``
    /// method instead.
    ///
    /// - Parameters:
    ///   - bufferPointer: A pointer to the next block of data for the ongoing
    /// digest calculation.
    mutating func update(bufferPointer: UnsafeRawBufferPointer)

    /// Finalizes the hash function and returns the computed digest.
    ///
    /// Call this method after you provide the hash function with all the data
    /// to hash using one or more calls to the ``update(data:)`` or
    /// ``update(bufferPointer:)`` method. After finalizing the hash function,
    /// discard it. To compute a new digest, create a new hash function with a
    /// call to the ``init()`` method.
    ///
    /// - Returns: The computed digest of the data.
    func finalize() -> Digest
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension HashFunction {
    /// Computes a digest of the buffer.
    ///
    /// - Parameters:
    ///   - bufferPointer: The buffer to be hashed.
    /// - Returns: The computed digest.
    @inlinable
    static func hash(bufferPointer: UnsafeRawBufferPointer) -> Digest {
        var hasher = Self()
        hasher.update(bufferPointer: bufferPointer)
        return hasher.finalize()
    }
    
    /// Computes the digest of the bytes in the given data instance and
    /// returns the computed digest.
    ///
    /// Use this method if all your data fits into a single data instance. If
    /// the data you want to hash is too large, initialize a hash function and
    /// use the ``update(data:)`` and ``finalize()`` methods to compute the
    /// digest in blocks.
    ///
    /// - Parameters:
    ///   - data: The data whose digest the hash function should compute. This can
    /// be any type that conforms to
    /// <doc://com.apple.documentation/documentation/foundation/dataprotocol>,
    /// like <doc://com.apple.documentation/documentation/foundation/data> or an
    /// array of <doc://com.apple.documentation/documentation/swift/uint8>
    /// instances.
    ///
    /// - Returns: The computed digest of the data.
    @inlinable
    public static func hash<D: DataProtocol>(data: D) -> Self.Digest {
        var hasher = Self()
        hasher.update(data: data)
        return hasher.finalize()
    }

    /// Incrementally updates the hash function with the given data.
    ///
    /// Call this method one or more times to provide data to the hash function
    /// in blocks. After providing the last block of data, call the
    /// ``finalize()`` method to get the computed digest. Don’t call the update
    /// method again after finalizing the hash function.
    ///
    /// - Parameters:
    ///   - data: The next block of data for the ongoing digest calculation. You
    /// can provide this as any type that conforms to
    /// <doc://com.apple.documentation/documentation/foundation/dataprotocol>,
    /// like <doc://com.apple.documentation/documentation/foundation/data> or an
    /// array of <doc://com.apple.documentation/documentation/swift/uint8>
    /// instances.
    @inlinable
    public mutating func update<D: DataProtocol>(data: D) {
        data.regions.forEach { (regionData) in
            regionData.withUnsafeBytes({ (dataPtr) in
                self.update(bufferPointer: dataPtr)
            })
        }
    }
}
#endif // Linux or !SwiftPM
