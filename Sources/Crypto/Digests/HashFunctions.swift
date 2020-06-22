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
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
typealias DigestImpl = CoreCryptoDigestImpl
#else
typealias DigestImpl = OpenSSLDigestImpl
#endif

import Foundation

/// Declares methods on cryptographic hash functions.
public protocol HashFunction {
    /// The block size of the hash function. It is different from the output size that can be retrieved from Digest.byteCount.
    static var blockByteCount: Int { get }
    #if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
    associatedtype Digest: CryptoKit.Digest
    #else
    associatedtype Digest: Crypto.Digest
    #endif

    /// Initializes the hasher instance.
    init()

    /// Updates the hasher with the buffer.
    ///
    /// - Parameter bufferPointer: The buffer to update the hash
    mutating func update(bufferPointer: UnsafeRawBufferPointer)

    /// Returns the digest from the input in the hash function instance.
    ///
    /// - Returns: The digest of the data
    func finalize() -> Digest
}

extension HashFunction {
    /// Computes a digest of the buffer.
    ///
    /// - Parameter bufferPointer: The buffer to be hashed
    /// - Returns: The computed digest
    @inlinable
    static func hash(bufferPointer: UnsafeRawBufferPointer) -> Digest {
        var hasher = Self()
        hasher.update(bufferPointer: bufferPointer)
        return hasher.finalize()
    }
    
    /// Computes a digest of the data.
    ///
    /// - Parameter data: The data to be hashed
    /// - Returns: The computed digest
    @inlinable
    public static func hash<D: DataProtocol>(data: D) -> Self.Digest {
        var hasher = Self()
        hasher.update(data: data)
        return hasher.finalize()
    }

    /// Updates the hasher with the data.
    ///
    /// - Parameter data: The data to update the hash
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
