//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

enum IntegerDecodingError: Error, Equatable {
    case incorrectNumberOfBytes(expected: Int, actual: Int)
}

extension FixedWidthInteger {
    /// Create an new value from a collection of its big endian bytes.
    ///
    /// - Parameter bytes: Big endian bytes.
    ///
    /// - Throws: A decoding error if the collection did not contain the exact number of bytes.
    init(bigEndianBytes bytes: some Collection<UInt8>) throws {
        guard bytes.count == Self.bitWidth / 8 else {
            throw IntegerDecodingError.incorrectNumberOfBytes(expected: Self.bitWidth / 8, actual: bytes.count)
        }

        self = 0
        var index = bytes.startIndex
        for _ in 0..<(Self.bitWidth / 8) {
            self <<= 8
            self |= Self(bytes[index])
            bytes.formIndex(after: &index)
        }
    }

    fileprivate init(bigEndianContiguousBytes bytes: some ContiguousBytes) throws {
        self = try bytes.withUnsafeBytes { try Self(bigEndianBytes: $0 ) }
    }

    /// Create an new value from its big endian bytes representation.
    ///
    /// - Parameter bytes: Big endian bytes.
    ///
    /// - Throws: A decoding error if the collection did not contain the exact number of bytes.
    init(bigEndianBytes bytes: Data) throws {
        self = try Self(bigEndianContiguousBytes: bytes)
    }

    /// The big endian bytes that represent this value.
    var bigEndianBytes: Data { Data(bigEndianBytesOf: self) }
}

extension Data {
    /// Creates a new instance initialized with the big endian bytes representation of the given integer.
    init(bigEndianBytesOf integer: some FixedWidthInteger) {
        self.init()
        self.append(bigEndianBytesOf: integer)
    }

    /// Appends the big endian bytes of the given integer.
    mutating func append<T: FixedWidthInteger>(bigEndianBytesOf integer: T) {
        let previousCount = self.count
        let newCount = previousCount + T.bitWidth / 8
        self.reserveCapacity(newCount)
        self.count = newCount
        self.withUnsafeMutableBytes {
            $0.storeBytes(of: integer.bigEndian, toByteOffset: previousCount, as: T.self)
        }
    }

    /// Removes and returns the first k bytes.
    mutating func popFirst(_ k: Int) -> Self {
        let prefix = self.prefix(k)
        self.removeFirst(k)
        return prefix
    }

    /// Removes and returns the first k bytes, decoded as a value of the given type from its big endian bytes.
    mutating func popFirst<T: FixedWidthInteger>(bigEndian: T.Type) throws -> T {
        let value = try T(bigEndianBytes: self.prefix(T.bitWidth / 8))
        self.removeFirst(T.bitWidth / 8)
        return value
    }
}
