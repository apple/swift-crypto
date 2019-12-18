//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
/// The SHA-256 Hash Function
@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
public struct SHA256: HashFunctionImplementationDetails {
    public static var blockByteCount: Int = 64
    public typealias Digest = SHA256Digest
    public static var byteCount = 32
    var impl: DigestImpl<SHA256>

    /// Initializes the hash function instance.
    public init() {
        self.impl = DigestImpl()
    }

    // Once https://github.com/apple/swift-evolution/pull/910 is landed,
    // we will be able to implement `init` here and remove the duplicate code.

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        self.impl.update(data: bufferPointer)
    }

    /// Returns the digest from the data input in the hash function instance.
    ///
    /// - Returns: The digest of the inputted data
    public func finalize() -> Self.Digest {
        return self.impl.finalize()
    }
}

/// The SHA-384 Hash Function
@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
public struct SHA384: HashFunctionImplementationDetails {
    public static var blockByteCount: Int = 128
    public typealias Digest = SHA384Digest
    public static var byteCount = 48
    var impl: DigestImpl<SHA384>

    public init() {
        self.impl = DigestImpl()
    }

    // Once https://github.com/apple/swift-evolution/pull/910 is landed,
    // we will be able to implement `init` here and remove the duplicate code.

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        self.impl.update(data: bufferPointer)
    }

    public func finalize() -> Self.Digest {
        return self.impl.finalize()
    }
}

/// The SHA-512 Hash Function
@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
public struct SHA512: HashFunctionImplementationDetails {
    public static var blockByteCount: Int = 128
    public typealias Digest = SHA512Digest
    public static var byteCount = 64
    var impl: DigestImpl<SHA512>

    /// Initializes the hash function instance.
    public init() {
        self.impl = DigestImpl()
    }

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        self.impl.update(data: bufferPointer)
    }

    public func finalize() -> Self.Digest {
        return self.impl.finalize()
    }
}
#endif // Linux or !SwiftPM
