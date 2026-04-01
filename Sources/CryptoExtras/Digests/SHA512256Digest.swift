//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// The output of a Secure Hashing Algorithm 2 (SHA-2) hash with a 256-bit digest
/// using the SHA-512/256 variant.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct SHA512256Digest: Digest {
    let bytes: (UInt64, UInt64, UInt64, UInt64)

    /// The number of bytes in the digest.
    public static var byteCount: Int {
        32
    }

    init?(bufferPointer: UnsafeRawBufferPointer) {
        guard bufferPointer.count == 32 else {
            return nil
        }

        var bytes = (UInt64(0), UInt64(0), UInt64(0), UInt64(0))
        withUnsafeMutableBytes(of: &bytes) { targetPtr in
            targetPtr.copyBytes(from: bufferPointer)
        }
        self.bytes = bytes
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
        try Swift.withUnsafeBytes(of: bytes) {
            let boundsCheckedPtr = UnsafeRawBufferPointer(
                start: $0.baseAddress,
                count: Self.byteCount
            )
            return try body(boundsCheckedPtr)
        }
    }
    #else
    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        try Swift.withUnsafeBytes(of: bytes) { ptr throws(E) -> R in
            let boundsCheckedPtr = UnsafeRawBufferPointer(
                start: ptr.baseAddress,
                count: Self.byteCount
            )
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
        return array.prefix(SHA512256Digest.byteCount)
    }

    #if !hasFeature(Embedded)
    /// A human-readable description of the digest.
    public var description: String {
        "SHA512-256 digest: \(toArray().hexString)"
    }
    #endif

    /// Hashes the essential components of the digest by feeding them into the
    /// given hash function.
    ///
    /// This method is part of the digest’s conformance to Swift standard library’s
    /// <doc://com.apple.documentation/documentation/swift/hashable> protocol, making
    /// it possible to compare digests. Don’t confuse that hashing with the
    /// cryptographically secure hashing that you use to create the digest in the
    /// first place by, for example, calling ``SHA512256/hash(data:)``.
    ///
    /// - Parameters:
    ///   - hasher: The hash function to use when combining the components of
    /// the digest.
    public func hash(into hasher: inout Hasher) {
        self.withUnsafeBytes { hasher.combine(bytes: $0) }
    }
}
