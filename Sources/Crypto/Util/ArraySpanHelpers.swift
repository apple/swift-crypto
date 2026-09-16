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

#if canImport(CryptoKit)
@_exported import CryptoKit
#else

extension InlineArray where Element == UInt8 {
    /// Copy of the bytes of the given raw span into this array. The span
    /// must have exactly count bytes in it.
    init(copying bytes: RawSpan) {
        precondition(count == bytes.byteCount)
        self.init { outputSpan in
            for i in 0..<count {
                outputSpan.append(bytes.unsafeLoad(fromByteOffset: i, as: UInt8.self))
            }
        }
    }
}

extension Array where Element == UInt8 {
    /// Copy of the bytes of the given raw span into this array. The span
    /// must have exactly count bytes in it.
    init(copying bytes: RawSpan) {
        self.init(unsafeUninitializedCapacity: bytes.byteCount) { outputBuffer, initializedCount in
            bytes.withUnsafeBytes { inputBuffer in
                UnsafeMutableRawBufferPointer(outputBuffer).copyMemory(from: inputBuffer)
            }
            initializedCount = bytes.byteCount
        }
    }
}

extension ContiguousArray where Element == UInt8 {
    /// Copy of the bytes of the given raw span into this array. The span
    /// must have exactly count bytes in it.
    init(copying bytes: RawSpan) {
        self.init(unsafeUninitializedCapacity: bytes.byteCount) { outputBuffer, initializedCount in
            bytes.withUnsafeBytes { inputBuffer in
                UnsafeMutableRawBufferPointer(outputBuffer).copyMemory(from: inputBuffer)
            }
            initializedCount = bytes.byteCount
        }
    }
}

extension OutputRawSpan {
    /// Append the contents of the given raw span to this output span.
    #if swift(<6.3)
    @_lifetime(self: copy self)
    #endif
    mutating func append(contentsOf bytes: RawSpan) {
        for i in 0..<bytes.byteCount {
            append(bytes.unsafeLoad(fromByteOffset: i, as: UInt8.self))
        }
    }
}

extension OutputSpan<UInt8> {
    /// Append the contents of the given raw span to this output span.
    #if swift(<6.3)
    @_lifetime(self: copy self)
    #endif
    mutating func append(contentsOf bytes: RawSpan) {
        for i in 0..<bytes.byteCount {
            append(bytes.unsafeLoad(fromByteOffset: i, as: UInt8.self))
        }
    }
}

extension UnsafeMutableRawBufferPointer {
    /// Copy the bytes from the source span into this beginning of this buffer.
    func copyBytes(from source: RawSpan) {
        precondition(source.byteCount <= self.count)
        for index in 0..<source.byteCount {
            self[index] = source.unsafeLoad(fromByteOffset: index, as: UInt8.self)
        }
    }
}

#endif
