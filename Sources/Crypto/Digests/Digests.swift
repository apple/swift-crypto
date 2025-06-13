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
// MARK: - Generated file, do NOT edit
// any edits of this file WILL be overwritten and thus discarded
// see section `gyb` in `README` for details.



// MARK: - SHA256Digest + DigestPrivate
/// The output of a Secure Hashing Algorithm 2 (SHA-2) hash with a 256-bit digest.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct SHA256Digest: DigestPrivate {
    let bytes: (UInt64, UInt64, UInt64, UInt64)
    
    init?(bufferPointer: UnsafeRawBufferPointer) {
        guard bufferPointer.count == 32 else {
            return nil
        }

        var bytes = (UInt64(0), UInt64(0), UInt64(0), UInt64(0))
        withUnsafeMutableBytes(of: &bytes) { targetPtr in
            targetPtr.copyMemory(from: bufferPointer)
        }
        self.bytes = bytes
    }
    
    /// The number of bytes in the digest.
    public static var byteCount: Int {
        return 32
    }
    
    /// Invokes the given closure with a buffer pointer covering the raw bytes of
    /// the digest.
    ///
    /// - Parameters:
    ///   - body: A closure that takes a raw buffer pointer to the bytes of the digest
    /// and returns the digest.
    ///
    /// - Returns: The digest, as returned from the body closure.
#if !hasFeature(Embedded)
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try Swift.withUnsafeBytes(of: bytes) {
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: $0.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }
#else
    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        return try Swift.withUnsafeBytes(of: bytes) { ptr throws(E) -> R in
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: ptr.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }
#endif

    private func toArray() -> ArraySlice<UInt8> {
        var array = [UInt8]()
        array.appendByte(bytes.0)
        array.appendByte(bytes.1)
        array.appendByte(bytes.2)
        array.appendByte(bytes.3)
        return array.prefix(SHA256Digest.byteCount)
    }

#if !hasFeature(Embedded)
    /// A human-readable description of the digest.
    public var description: String {
        return "\("SHA256") digest: \(toArray().hexString)"
    }
#endif

    /// Hashes the essential components of the digest by feeding them into the
    /// given hash function.
    ///
    /// This method is part of the digest’s conformance to Swift standard library’s
    /// <doc://com.apple.documentation/documentation/swift/hashable> protocol, making
    /// it possible to compare digests. Don’t confuse that hashing with the
    /// cryptographically secure hashing that you use to create the digest in the
    /// first place by, for example, calling ``SHA256/hash(data:)``.
    ///
    /// - Parameters:
    ///   - hasher: The hash function to use when combining the components of
    /// the digest.
    public func hash(into hasher: inout Hasher) {
        self.withUnsafeBytes { hasher.combine(bytes: $0) }
    }
}


// MARK: - SHA384Digest + DigestPrivate
/// The output of a Secure Hashing Algorithm 2 (SHA-2) hash with a 384-bit digest.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct SHA384Digest: DigestPrivate {
    let bytes: (UInt64, UInt64, UInt64, UInt64, UInt64, UInt64)
    
    init?(bufferPointer: UnsafeRawBufferPointer) {
        guard bufferPointer.count == 48 else {
            return nil
        }

        var bytes = (UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0))
        withUnsafeMutableBytes(of: &bytes) { targetPtr in
            targetPtr.copyMemory(from: bufferPointer)
        }
        self.bytes = bytes
    }
    
    /// The number of bytes in the digest.
    public static var byteCount: Int {
        return 48
    }
    
    /// Invokes the given closure with a buffer pointer covering the raw bytes of
    /// the digest.
    ///
    /// - Parameters:
    ///   - body: A closure that takes a raw buffer pointer to the bytes of the digest
    /// and returns the digest.
    ///
    /// - Returns: The digest, as returned from the body closure.
#if !hasFeature(Embedded)
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try Swift.withUnsafeBytes(of: bytes) {
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: $0.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }
#else
    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        return try Swift.withUnsafeBytes(of: bytes) { ptr throws(E) -> R in
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: ptr.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }
#endif

    private func toArray() -> ArraySlice<UInt8> {
        var array = [UInt8]()
        array.appendByte(bytes.0)
        array.appendByte(bytes.1)
        array.appendByte(bytes.2)
        array.appendByte(bytes.3)
        array.appendByte(bytes.4)
        array.appendByte(bytes.5)
        return array.prefix(SHA384Digest.byteCount)
    }

#if !hasFeature(Embedded)
    /// A human-readable description of the digest.
    public var description: String {
        return "\("SHA384") digest: \(toArray().hexString)"
    }
#endif

    /// Hashes the essential components of the digest by feeding them into the
    /// given hash function.
    ///
    /// This method is part of the digest’s conformance to Swift standard library’s
    /// <doc://com.apple.documentation/documentation/swift/hashable> protocol, making
    /// it possible to compare digests. Don’t confuse that hashing with the
    /// cryptographically secure hashing that you use to create the digest in the
    /// first place by, for example, calling ``SHA384/hash(data:)``.
    ///
    /// - Parameters:
    ///   - hasher: The hash function to use when combining the components of
    /// the digest.
    public func hash(into hasher: inout Hasher) {
        self.withUnsafeBytes { hasher.combine(bytes: $0) }
    }
}


// MARK: - SHA512Digest + DigestPrivate
/// The output of a Secure Hashing Algorithm 2 (SHA-2) hash with a 512-bit digest.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct SHA512Digest: DigestPrivate {
    let bytes: (UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64)
    
    init?(bufferPointer: UnsafeRawBufferPointer) {
        guard bufferPointer.count == 64 else {
            return nil
        }

        var bytes = (UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0))
        withUnsafeMutableBytes(of: &bytes) { targetPtr in
            targetPtr.copyMemory(from: bufferPointer)
        }
        self.bytes = bytes
    }
    
    /// The number of bytes in the digest.
    public static var byteCount: Int {
        return 64
    }
    
    /// Invokes the given closure with a buffer pointer covering the raw bytes of
    /// the digest.
    ///
    /// - Parameters:
    ///   - body: A closure that takes a raw buffer pointer to the bytes of the digest
    /// and returns the digest.
    ///
    /// - Returns: The digest, as returned from the body closure.
#if !hasFeature(Embedded)
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try Swift.withUnsafeBytes(of: bytes) {
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: $0.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }
#else
    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        return try Swift.withUnsafeBytes(of: bytes) { ptr throws(E) -> R in
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: ptr.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }
#endif

    private func toArray() -> ArraySlice<UInt8> {
        var array = [UInt8]()
        array.appendByte(bytes.0)
        array.appendByte(bytes.1)
        array.appendByte(bytes.2)
        array.appendByte(bytes.3)
        array.appendByte(bytes.4)
        array.appendByte(bytes.5)
        array.appendByte(bytes.6)
        array.appendByte(bytes.7)
        return array.prefix(SHA512Digest.byteCount)
    }

#if !hasFeature(Embedded)
    /// A human-readable description of the digest.
    public var description: String {
        return "\("SHA512") digest: \(toArray().hexString)"
    }
#endif

    /// Hashes the essential components of the digest by feeding them into the
    /// given hash function.
    ///
    /// This method is part of the digest’s conformance to Swift standard library’s
    /// <doc://com.apple.documentation/documentation/swift/hashable> protocol, making
    /// it possible to compare digests. Don’t confuse that hashing with the
    /// cryptographically secure hashing that you use to create the digest in the
    /// first place by, for example, calling ``SHA512/hash(data:)``.
    ///
    /// - Parameters:
    ///   - hasher: The hash function to use when combining the components of
    /// the digest.
    public func hash(into hasher: inout Hasher) {
        self.withUnsafeBytes { hasher.combine(bytes: $0) }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Insecure {
// MARK: - SHA1Digest + DigestPrivate
/// The output of a SHA1 hash.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct SHA1Digest: DigestPrivate {
    let bytes: (UInt64, UInt64, UInt64)
    
    init?(bufferPointer: UnsafeRawBufferPointer) {
        guard bufferPointer.count == 20 else {
            return nil
        }

        var bytes = (UInt64(0), UInt64(0), UInt64(0))
        withUnsafeMutableBytes(of: &bytes) { targetPtr in
            targetPtr.copyMemory(from: bufferPointer)
        }
        self.bytes = bytes
    }
    
    /// The number of bytes in the digest.
    public static var byteCount: Int {
        return 20
    }
    
    /// Invokes the given closure with a buffer pointer covering the raw bytes of
    /// the digest.
    ///
    /// - Parameters:
    ///   - body: A closure that takes a raw buffer pointer to the bytes of the digest
    /// and returns the digest.
    ///
    /// - Returns: The digest, as returned from the body closure.
#if !hasFeature(Embedded)
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try Swift.withUnsafeBytes(of: bytes) {
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: $0.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }
#else
    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        return try Swift.withUnsafeBytes(of: bytes) { ptr throws(E) -> R in
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: ptr.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }
#endif

    private func toArray() -> ArraySlice<UInt8> {
        var array = [UInt8]()
        array.appendByte(bytes.0)
        array.appendByte(bytes.1)
        array.appendByte(bytes.2)
        return array.prefix(SHA1Digest.byteCount)
    }

#if !hasFeature(Embedded)
    /// A human-readable description of the digest.
    public var description: String {
        return "\("SHA1") digest: \(toArray().hexString)"
    }
#endif

    /// Hashes the essential components of the digest by feeding them into the
    /// given hash function.
    ///
    /// This method is part of the digest’s conformance to Swift standard library’s
    /// <doc://com.apple.documentation/documentation/swift/hashable> protocol, making
    /// it possible to compare digests. Don’t confuse that hashing with the
    /// cryptographically secure hashing that you use to create the digest in the
    /// first place by, for example, calling ``Insecure/SHA1/hash(data:)``.
    ///
    /// - Parameters:
    ///   - hasher: The hash function to use when combining the components of
    /// the digest.
    public func hash(into hasher: inout Hasher) {
        self.withUnsafeBytes { hasher.combine(bytes: $0) }
    }
}
}
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Insecure {
// MARK: - MD5Digest + DigestPrivate
/// The output of a MD5 hash.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct MD5Digest: DigestPrivate {
    let bytes: (UInt64, UInt64)
    
    init?(bufferPointer: UnsafeRawBufferPointer) {
        guard bufferPointer.count == 16 else {
            return nil
        }

        var bytes = (UInt64(0), UInt64(0))
        withUnsafeMutableBytes(of: &bytes) { targetPtr in
            targetPtr.copyMemory(from: bufferPointer)
        }
        self.bytes = bytes
    }
    
    /// The number of bytes in the digest.
    public static var byteCount: Int {
        return 16
    }
    
    /// Invokes the given closure with a buffer pointer covering the raw bytes of
    /// the digest.
    ///
    /// - Parameters:
    ///   - body: A closure that takes a raw buffer pointer to the bytes of the digest
    /// and returns the digest.
    ///
    /// - Returns: The digest, as returned from the body closure.
#if !hasFeature(Embedded)
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try Swift.withUnsafeBytes(of: bytes) {
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: $0.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }
#else
    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        return try Swift.withUnsafeBytes(of: bytes) { ptr throws(E) -> R in
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: ptr.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }
#endif

    private func toArray() -> ArraySlice<UInt8> {
        var array = [UInt8]()
        array.appendByte(bytes.0)
        array.appendByte(bytes.1)
        return array.prefix(MD5Digest.byteCount)
    }

#if !hasFeature(Embedded)
    /// A human-readable description of the digest.
    public var description: String {
        return "\("MD5") digest: \(toArray().hexString)"
    }
#endif

    /// Hashes the essential components of the digest by feeding them into the
    /// given hash function.
    ///
    /// This method is part of the digest’s conformance to Swift standard library’s
    /// <doc://com.apple.documentation/documentation/swift/hashable> protocol, making
    /// it possible to compare digests. Don’t confuse that hashing with the
    /// cryptographically secure hashing that you use to create the digest in the
    /// first place by, for example, calling ``Insecure/MD5/hash(data:)``.
    ///
    /// - Parameters:
    ///   - hasher: The hash function to use when combining the components of
    /// the digest.
    public func hash(into hasher: inout Hasher) {
        self.withUnsafeBytes { hasher.combine(bytes: $0) }
    }
}
}


#if !CRYPTOKIT_IN_SEP

// MARK: - SHA3_256Digest + DigestPrivate
/// The output of a Secure Hashing Algorithm 3 (SHA-2) hash with a 256-bit digest.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct SHA3_256Digest: DigestPrivate {
    let bytes: (UInt64, UInt64, UInt64, UInt64)

    init?(bufferPointer: UnsafeRawBufferPointer) {
        guard bufferPointer.count == 32 else {
            return nil
        }

        var bytes = (UInt64(0), UInt64(0), UInt64(0), UInt64(0))
        withUnsafeMutableBytes(of: &bytes) { targetPtr in
            targetPtr.copyMemory(from: bufferPointer)
        }
        self.bytes = bytes
    }

    /// The number of bytes in the digest.
    public static var byteCount: Int {
        return 32
    }

    /// Invokes the given closure with a buffer pointer covering the raw bytes of
    /// the digest.
    ///
    /// - Parameters:
    ///   - body: A closure that takes a raw buffer pointer to the bytes of the digest
    /// and returns the digest.
    ///
    /// - Returns: The digest, as returned from the body closure.
#if !hasFeature(Embedded)
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try Swift.withUnsafeBytes(of: bytes) {
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: $0.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }
#else
    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        return try Swift.withUnsafeBytes(of: bytes) { ptr throws(E) -> R in
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: ptr.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }
#endif

    private func toArray() -> ArraySlice<UInt8> {
        var array = [UInt8]()
        array.appendByte(bytes.0)
        array.appendByte(bytes.1)
        array.appendByte(bytes.2)
        array.appendByte(bytes.3)
        return array.prefix(upTo: SHA3_256Digest.byteCount)
    }

#if !hasFeature(Embedded)
    /// A human-readable description of the digest.
    public var description: String {
        return "\("SHA3_256") digest: \(toArray().hexString)"
    }
#endif

    /// Hashes the essential components of the digest by feeding them into the
    /// given hash function.
    ///
    /// This method is part of the digest’s conformance to Swift standard library’s
    /// <doc://com.apple.documentation/documentation/swift/hashable> protocol, making
    /// it possible to compare digests. Don’t confuse that hashing with the
    /// cryptographically secure hashing that you use to create the digest in the
    /// first place by, for example, calling ``SHA3_256/hash(data:)``.
    ///
    /// - Parameters:
    ///   - hasher: The hash function to use when combining the components of
    /// the digest.
    public func hash(into hasher: inout Hasher) {
        self.withUnsafeBytes { hasher.combine(bytes: $0) }
    }
}
// MARK: - SHA3_384Digest + DigestPrivate
/// The output of a Secure Hashing Algorithm 3 (SHA-2) hash with a 384-bit digest.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct SHA3_384Digest: DigestPrivate {
    let bytes: (UInt64, UInt64, UInt64, UInt64, UInt64, UInt64)

    init?(bufferPointer: UnsafeRawBufferPointer) {
        guard bufferPointer.count == 48 else {
            return nil
        }

        var bytes = (UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0))
        withUnsafeMutableBytes(of: &bytes) { targetPtr in
            targetPtr.copyMemory(from: bufferPointer)
        }
        self.bytes = bytes
    }

    /// The number of bytes in the digest.
    public static var byteCount: Int {
        return 48
    }

    /// Invokes the given closure with a buffer pointer covering the raw bytes of
    /// the digest.
    ///
    /// - Parameters:
    ///   - body: A closure that takes a raw buffer pointer to the bytes of the digest
    /// and returns the digest.
    ///
    /// - Returns: The digest, as returned from the body closure.
#if !hasFeature(Embedded)
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try Swift.withUnsafeBytes(of: bytes) {
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: $0.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }
#else
    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        return try Swift.withUnsafeBytes(of: bytes) { ptr throws(E) -> R in
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: ptr.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }
#endif

    private func toArray() -> ArraySlice<UInt8> {
        var array = [UInt8]()
        array.appendByte(bytes.0)
        array.appendByte(bytes.1)
        array.appendByte(bytes.2)
        array.appendByte(bytes.3)
        array.appendByte(bytes.4)
        array.appendByte(bytes.5)
        return array.prefix(upTo: SHA3_384Digest.byteCount)
    }

#if !hasFeature(Embedded)
    /// A human-readable description of the digest.
    public var description: String {
        return "\("SHA3_384") digest: \(toArray().hexString)"
    }
#endif

    /// Hashes the essential components of the digest by feeding them into the
    /// given hash function.
    ///
    /// This method is part of the digest’s conformance to Swift standard library’s
    /// <doc://com.apple.documentation/documentation/swift/hashable> protocol, making
    /// it possible to compare digests. Don’t confuse that hashing with the
    /// cryptographically secure hashing that you use to create the digest in the
    /// first place by, for example, calling ``SHA3_384/hash(data:)``.
    ///
    /// - Parameters:
    ///   - hasher: The hash function to use when combining the components of
    /// the digest.
    public func hash(into hasher: inout Hasher) {
        self.withUnsafeBytes { hasher.combine(bytes: $0) }
    }
}
// MARK: - SHA3_512Digest + DigestPrivate
/// The output of a Secure Hashing Algorithm 3 (SHA-2) hash with a 512-bit digest.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct SHA3_512Digest: DigestPrivate {
    let bytes: (UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64)

    init?(bufferPointer: UnsafeRawBufferPointer) {
        guard bufferPointer.count == 64 else {
            return nil
        }

        var bytes = (UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0))
        withUnsafeMutableBytes(of: &bytes) { targetPtr in
            targetPtr.copyMemory(from: bufferPointer)
        }
        self.bytes = bytes
    }

    /// The number of bytes in the digest.
    public static var byteCount: Int {
        return 64
    }

    /// Invokes the given closure with a buffer pointer covering the raw bytes of
    /// the digest.
    ///
    /// - Parameters:
    ///   - body: A closure that takes a raw buffer pointer to the bytes of the digest
    /// and returns the digest.
    ///
    /// - Returns: The digest, as returned from the body closure.
#if !hasFeature(Embedded)
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try Swift.withUnsafeBytes(of: bytes) {
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: $0.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }
#else
    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        return try Swift.withUnsafeBytes(of: bytes) { ptr throws(E) -> R in
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: ptr.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }
#endif

    private func toArray() -> ArraySlice<UInt8> {
        var array = [UInt8]()
        array.appendByte(bytes.0)
        array.appendByte(bytes.1)
        array.appendByte(bytes.2)
        array.appendByte(bytes.3)
        array.appendByte(bytes.4)
        array.appendByte(bytes.5)
        array.appendByte(bytes.6)
        array.appendByte(bytes.7)
        return array.prefix(upTo: SHA3_512Digest.byteCount)
    }

#if !hasFeature(Embedded)
    /// A human-readable description of the digest.
    public var description: String {
        return "\("SHA3_512") digest: \(toArray().hexString)"
    }
#endif

    /// Hashes the essential components of the digest by feeding them into the
    /// given hash function.
    ///
    /// This method is part of the digest’s conformance to Swift standard library’s
    /// <doc://com.apple.documentation/documentation/swift/hashable> protocol, making
    /// it possible to compare digests. Don’t confuse that hashing with the
    /// cryptographically secure hashing that you use to create the digest in the
    /// first place by, for example, calling ``SHA3_512/hash(data:)``.
    ///
    /// - Parameters:
    ///   - hasher: The hash function to use when combining the components of
    /// the digest.
    public func hash(into hasher: inout Hasher) {
        self.withUnsafeBytes { hasher.combine(bytes: $0) }
    }
}
#endif // !CRYPTOKIT_IN_SEP
#endif // Linux or !SwiftPM
