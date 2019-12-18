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

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
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
        return try Swift.withUnsafeBytes(of: self.bytes) {
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: $0.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }

    private func toArray() -> ArraySlice<UInt8> {
        var array = [UInt8]()
        array.appendByte(self.bytes.0)
        array.appendByte(self.bytes.1)
        array.appendByte(self.bytes.2)
        array.appendByte(self.bytes.3)
        return array.prefix(upTo: SHA256Digest.byteCount)
    }

    public var description: String {
        return "\("SHA256") digest: \(self.toArray().hexString)"
    }

    public func hash(into hasher: inout Hasher) {
        self.withUnsafeBytes { hasher.combine(bytes: $0) }
    }
}

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
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
        return try Swift.withUnsafeBytes(of: self.bytes) {
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: $0.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }

    private func toArray() -> ArraySlice<UInt8> {
        var array = [UInt8]()
        array.appendByte(self.bytes.0)
        array.appendByte(self.bytes.1)
        array.appendByte(self.bytes.2)
        array.appendByte(self.bytes.3)
        array.appendByte(self.bytes.4)
        array.appendByte(self.bytes.5)
        return array.prefix(upTo: SHA384Digest.byteCount)
    }

    public var description: String {
        return "\("SHA384") digest: \(self.toArray().hexString)"
    }

    public func hash(into hasher: inout Hasher) {
        self.withUnsafeBytes { hasher.combine(bytes: $0) }
    }
}

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
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
        return try Swift.withUnsafeBytes(of: self.bytes) {
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: $0.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }

    private func toArray() -> ArraySlice<UInt8> {
        var array = [UInt8]()
        array.appendByte(self.bytes.0)
        array.appendByte(self.bytes.1)
        array.appendByte(self.bytes.2)
        array.appendByte(self.bytes.3)
        array.appendByte(self.bytes.4)
        array.appendByte(self.bytes.5)
        array.appendByte(self.bytes.6)
        array.appendByte(self.bytes.7)
        return array.prefix(upTo: SHA512Digest.byteCount)
    }

    public var description: String {
        return "\("SHA512") digest: \(self.toArray().hexString)"
    }

    public func hash(into hasher: inout Hasher) {
        self.withUnsafeBytes { hasher.combine(bytes: $0) }
    }
}

extension Insecure {
    @available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
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
            return try Swift.withUnsafeBytes(of: self.bytes) {
                let boundsCheckedPtr = UnsafeRawBufferPointer(start: $0.baseAddress,
                                                              count: Self.byteCount)
                return try body(boundsCheckedPtr)
            }
        }

        private func toArray() -> ArraySlice<UInt8> {
            var array = [UInt8]()
            array.appendByte(self.bytes.0)
            array.appendByte(self.bytes.1)
            array.appendByte(self.bytes.2)
            return array.prefix(upTo: SHA1Digest.byteCount)
        }

        public var description: String {
            return "\("SHA1") digest: \(self.toArray().hexString)"
        }

        public func hash(into hasher: inout Hasher) {
            self.withUnsafeBytes { hasher.combine(bytes: $0) }
        }
    }
}

extension Insecure {
    @available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
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
            return try Swift.withUnsafeBytes(of: self.bytes) {
                let boundsCheckedPtr = UnsafeRawBufferPointer(start: $0.baseAddress,
                                                              count: Self.byteCount)
                return try body(boundsCheckedPtr)
            }
        }

        private func toArray() -> ArraySlice<UInt8> {
            var array = [UInt8]()
            array.appendByte(self.bytes.0)
            array.appendByte(self.bytes.1)
            return array.prefix(upTo: MD5Digest.byteCount)
        }

        public var description: String {
            return "\("MD5") digest: \(self.toArray().hexString)"
        }

        public func hash(into hasher: inout Hasher) {
            self.withUnsafeBytes { hasher.combine(bytes: $0) }
        }
    }
}
#endif // Linux or !SwiftPM
