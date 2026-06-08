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

#if CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
import SwiftSystem
#elseif CRYPTOKIT_NO_IMPORT_FOUNDATION
#else
#if canImport(FoundationEssentials)
public import FoundationEssentials
#else
public import Foundation
#endif
#endif

/// The sizes that a symmetric cryptographic key can take.
///
/// When creating a new ``SymmetricKey`` instance with a call to its
/// ``SymmetricKey/init(size:)`` initializer, you typically use one of the
/// standard key sizes, like ``bits128``, ``bits192``, or ``bits256``. When you
/// need a key with a non-standard length, use the ``init(bitCount:)``
/// initializer to create a `SymmetricKeySize` instance with a custom bit count.
#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.13, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, visionOS 1.0, *)
#endif
public struct SymmetricKeySize: Sendable {
    /// The number of bits in the key.
    public let bitCount: Int

    /// A size of 128 bits.
    public static var bits128: SymmetricKeySize {
        return self.init(bitCount: 128)
    }

    /// A size of 192 bits.
    public static var bits192: SymmetricKeySize {
        return self.init(bitCount: 192)
    }

    /// A size of 256 bits.
    public static var bits256: SymmetricKeySize {
        return self.init(bitCount: 256)
    }
    
    /// Creates a new key size of the given length.
    ///
    /// In most cases, you can use one of the standard key sizes, like bits256.
    /// If instead you need a key with a non-standard size, use the
    /// ``init(bitCount:)`` initializer to create a custom key size.
    ///
    /// - Parameters:
    ///   - bitCount: The number of bits in the key size.
    public init(bitCount: Int) {
        precondition(bitCount > 0 && bitCount % 8 == 0)
        self.bitCount = bitCount
    }
}

/// A symmetric cryptographic key.
///
/// You typically derive a symmetric key from an instance of a shared secret
/// (``SharedSecret``) that you obtain through key agreement. You use a
/// symmetric key to compute a message authentication code like ``HMAC``, or to
/// open and close a sealed box (``ChaChaPoly/SealedBox`` or
/// ``AES/GCM/SealedBox``) using a cipher like ``ChaChaPoly`` or ``AES``.
#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.13, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, visionOS 1.0, *)
#endif
public struct SymmetricKey: ContiguousBytes, Sendable {
    let sb: SecureBytes

    /// Invokes the given closure with a buffer pointer covering the raw bytes
    /// of the key.
    ///
    /// - Parameters:
    ///   - body: A closure that takes a raw buffer pointer to the bytes of the
    /// key and returns the key.
    ///
    /// - Returns: The key, as returned from the body closure.
    #if hasFeature(Embedded)
    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        return try sb.withUnsafeBytes(body)
    }
    #else
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try sb.withUnsafeBytes(body)
    }
    #endif

    /// Access the raw bytes of the key.
#if !CRYPTOKIT_STATIC_LIBRARY
    @available(iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0, macCatalyst 27.0, visionOS 27.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
    @available(iOS 14.0, macOS 10.13, watchOS 7.0, tvOS 14.0, macCatalyst 14.0, visionOS 1.0, *)
#endif
    public var bytes: RawSpan {
        sb.bytes
    }

    /// Creates a key from the given data.
    ///
    /// - Parameters:
    ///   - data: The contiguous bytes from which to create the key.
    public init<D: ContiguousBytes>(data: D) {
        self.init(key: SecureBytes(bytes: data))
    }

    /// Creates a key from the given data.
    ///
    /// - Parameters:
    ///   - bytes: The span of bytes from which to create the key.
    ///
    /// Note: historical version of init(copying:) below, SPI only.
    @inlinable
    internal init(bytes: RawSpan) {
        self = bytes.withUnsafeBytes { SymmetricKey(data: $0) }
    }

    /// Creates a key from the given data.
    ///
    /// - Parameters:
    ///   - bytes: The span of bytes from which to create the key.
    @inlinable
    public init(copying bytes: RawSpan) {
        self = bytes.withUnsafeBytes { SymmetricKey(data: $0) }
    }

    /// Creates a key from the given data, zeroing out the bytes afterward.
    ///
    /// - Parameters:
    ///   - byte: The span of bytes from which to create the key.
    @available(iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0, macCatalyst 27.0, visionOS 27.0, *)
    public init(copyingWithZeroing bytes: inout MutableRawSpan) {
        self = bytes.withUnsafeBytes { SymmetricKey(data: $0) }
        bytes.withUnsafeMutableBytes { $0.zeroize() }
    }

    /// Generates a new random key of the given size.
    ///
    /// - Parameters:
    ///   - size: The size of the key to generate. You can use one of the standard
    /// sizes, like ``SymmetricKeySize/bits256``, or you can create a key of
    /// custom length by initializing a ``SymmetricKeySize`` instance with a
    /// non-standard value.
    public init(size: SymmetricKeySize) {
        self.init(key: SecureBytes(count: Int(size.bitCount / 8)))
    }

    #if hasFeature(Embedded)
    internal init<E: Error>(unsafeUninitializedCapacity: Int, initializingWith callback: (inout UnsafeMutableRawBufferPointer, inout Int) throws(E) -> Void) throws(E) {
        self.init(key: try SecureBytes(unsafeUninitializedCapacity: unsafeUninitializedCapacity, initializingWith: callback))
    }
    #else
    internal init(unsafeUninitializedCapacity: Int, initializingWith callback: (inout UnsafeMutableRawBufferPointer, inout Int) throws -> Void) rethrows {
        self.init(key: try SecureBytes(unsafeUninitializedCapacity: unsafeUninitializedCapacity, initializingWith: callback))
    }
    #endif

    /// Create a symmetric key with a closure that will initialize the memory.
    internal init<E: Error>(capacity: Int, initializingWith callback: (inout OutputRawSpan) throws(E) -> Void) throws(E) {
        self.init(key: try SecureBytes(capacity: capacity, initializingWith: callback))
    }

    /// Creates a new key of the given size where the key contents are initialized via a callback.
    ///
    /// - Parameters:
    ///   - size: The size of the key to generate. You can use one of the standard
    /// sizes, like ``SymmetricKeySize/bits256``, or you can create a key of
    /// custom length by initializing a ``SymmetricKeySize`` instance with a
    /// non-standard value.
    ///   - callback: A callback that will be invoked to initialize the contents
    /// of the key. It must initialize the full set of size.bitCount / 8 bytes
    /// in the provided output span.
#if !CRYPTOKIT_STATIC_LIBRARY
    @available(iOS 27.0, macOS 27.0, watchOS 27.0, tvOS 27.0, macCatalyst 27.0, visionOS 27.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
    @available(iOS 13.0, macOS 10.13, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, visionOS 1.0, *)
#endif
    public init<E: Error>(size: SymmetricKeySize, initializingWith callback: (inout OutputRawSpan) throws(E) -> Void) throws(E) {
        try self.init(capacity: Int(size.bitCount / 8), initializingWith: callback)
    }

    // Fast-path alias for cases whe know we have a SecureBytes object.
    internal init(data: SecureBytes) {
        self.init(key: data)
    }

    /// The number of bits in the key.
    public var bitCount: Int {
        return self.byteCount * 8
    }
    
    var byteCount: Int {
        return self.withUnsafeBytes({ (rbf) in
            return rbf.count
        })
    }

    private init(key: SecureBytes) {
        sb = key
    }
}

#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 13.0, macOS 10.13, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, visionOS 1.0, *)
#endif
extension SymmetricKey: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        return safeCompare(lhs, rhs)
    }
}

#endif // Linux or !SwiftPM
