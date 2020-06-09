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
/// The SHA-256 Hash Function
public struct SHA256: HashFunctionImplementationDetails {
    public static var blockByteCount: Int {
        get { return 64 }
        
        set { fatalError("Cannot set SHA256.blockByteCount") }
    }
    public static var byteCount: Int {
        get { return 32 }
        
        set { fatalError("Cannot set SHA256.byteCount") }
    }
    public typealias Digest = SHA256Digest
    
    var impl: DigestImpl<SHA256>

    /// Initializes the hash function instance.
    public init() {
        impl = DigestImpl()
    }

    // Once https://github.com/apple/swift-evolution/pull/910 is landed,
    // we will be able to implement `init` here and remove the duplicate code.

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        impl.update(data: bufferPointer)
    }

    /// Returns the digest from the data input in the hash function instance.
    ///
    /// - Returns: The digest of the inputted data
    public func finalize() -> Self.Digest {
        return impl.finalize()
    }
}

/// The SHA-384 Hash Function
public struct SHA384: HashFunctionImplementationDetails {
    public static var blockByteCount: Int {
        get { return 128 }
        
        set { fatalError("Cannot set SHA384.blockByteCount") }
    }
    public static var byteCount: Int {
        get { return 48 }
        
        set { fatalError("Cannot set SHA384.byteCount") }
    }
    
    public typealias Digest = SHA384Digest
    var impl: DigestImpl<SHA384>

    public init() {
        impl = DigestImpl()
    }

    // Once https://github.com/apple/swift-evolution/pull/910 is landed,
    // we will be able to implement `init` here and remove the duplicate code.

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        impl.update(data: bufferPointer)
    }

    public func finalize() -> Self.Digest {
        return impl.finalize()
    }
}

/// The SHA-512 Hash Function
public struct SHA512: HashFunctionImplementationDetails {
    public static var blockByteCount: Int {
        get { return 128 }
        
        set { fatalError("Cannot set SHA512.blockByteCount") }
    }
    public static var byteCount: Int {
        get { return 64 }
        
        set { fatalError("Cannot set SHA512.byteCount") }
    }
    public typealias Digest = SHA512Digest
    
    var impl: DigestImpl<SHA512>

    /// Initializes the hash function instance.
    public init() {
        impl = DigestImpl()
    }

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        impl.update(data: bufferPointer)
    }

    public func finalize() -> Self.Digest {
        return impl.finalize()
    }
}
#endif // Linux or !SwiftPM
