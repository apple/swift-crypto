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
// MARK: - Generated file, do NOT edit
// any edits of this file WILL be overwritten and thus discarded
// see section `gyb` in `README` for details.

// MARK: - SHA256Digest + DigestPrivate
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
    
    public static var byteCount: Int {
        return 32
    }
    
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try Swift.withUnsafeBytes(of: bytes) {
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: $0.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }

    private func toArray() -> ArraySlice<UInt8> {
        var array = [UInt8]()
        array.appendByte(bytes.0)
        array.appendByte(bytes.1)
        array.appendByte(bytes.2)
        array.appendByte(bytes.3)
        return array.prefix(upTo: SHA256Digest.byteCount)
    }
    
    public var description: String {
        return "\("SHA256") digest: \(toArray().hexString)"
    }
    
    public func hash(into hasher: inout Hasher) {
        self.withUnsafeBytes { hasher.combine(bytes: $0) }
    }
}


// MARK: - SHA384Digest + DigestPrivate
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
    
    public static var byteCount: Int {
        return 48
    }
    
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try Swift.withUnsafeBytes(of: bytes) {
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: $0.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }

    private func toArray() -> ArraySlice<UInt8> {
        var array = [UInt8]()
        array.appendByte(bytes.0)
        array.appendByte(bytes.1)
        array.appendByte(bytes.2)
        array.appendByte(bytes.3)
        array.appendByte(bytes.4)
        array.appendByte(bytes.5)
        return array.prefix(upTo: SHA384Digest.byteCount)
    }
    
    public var description: String {
        return "\("SHA384") digest: \(toArray().hexString)"
    }
    
    public func hash(into hasher: inout Hasher) {
        self.withUnsafeBytes { hasher.combine(bytes: $0) }
    }
}


// MARK: - SHA512Digest + DigestPrivate
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
    
    public static var byteCount: Int {
        return 64
    }
    
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try Swift.withUnsafeBytes(of: bytes) {
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: $0.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }

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
        return array.prefix(upTo: SHA512Digest.byteCount)
    }
    
    public var description: String {
        return "\("SHA512") digest: \(toArray().hexString)"
    }
    
    public func hash(into hasher: inout Hasher) {
        self.withUnsafeBytes { hasher.combine(bytes: $0) }
    }
}

extension Insecure{
// MARK: - SHA1Digest + DigestPrivate
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
    
    public static var byteCount: Int {
        return 20
    }
    
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try Swift.withUnsafeBytes(of: bytes) {
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: $0.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }

    private func toArray() -> ArraySlice<UInt8> {
        var array = [UInt8]()
        array.appendByte(bytes.0)
        array.appendByte(bytes.1)
        array.appendByte(bytes.2)
        return array.prefix(upTo: SHA1Digest.byteCount)
    }
    
    public var description: String {
        return "\("SHA1") digest: \(toArray().hexString)"
    }
    
    public func hash(into hasher: inout Hasher) {
        self.withUnsafeBytes { hasher.combine(bytes: $0) }
    }
}
}
extension Insecure{
// MARK: - MD5Digest + DigestPrivate
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
    
    public static var byteCount: Int {
        return 16
    }
    
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try Swift.withUnsafeBytes(of: bytes) {
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: $0.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }

    private func toArray() -> ArraySlice<UInt8> {
        var array = [UInt8]()
        array.appendByte(bytes.0)
        array.appendByte(bytes.1)
        return array.prefix(upTo: MD5Digest.byteCount)
    }
    
    public var description: String {
        return "\("MD5") digest: \(toArray().hexString)"
    }
    
    public func hash(into hasher: inout Hasher) {
        self.withUnsafeBytes { hasher.combine(bytes: $0) }
    }
}
}
#endif // Linux or !SwiftPM
