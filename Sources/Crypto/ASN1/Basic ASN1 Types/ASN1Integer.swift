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
#else
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
#endif

/// A protocol that represents any internal object that can present itself as a INTEGER, or be parsed from
/// a INTEGER.
///
/// This is not a very good solution for a fully-fledged ASN.1 library: we'd rather have a better numerics
/// protocol that could both initialize from and serialize to either bytes or words. However, no such
/// protocol exists today.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
protocol ASN1IntegerRepresentable: ASN1ImplicitlyTaggable {
    associatedtype IntegerBytes: RandomAccessCollection where IntegerBytes.Element == UInt8

    /// Whether this type can represent signed integers. If this is set to false, the serializer and
    /// parser will automatically handle padding with leading zero bytes as needed.
    static var isSigned: Bool { get }

    init(asn1IntegerBytes: ArraySlice<UInt8>) throws(CryptoKitMetaError)

    func withBigEndianIntegerBytes<ReturnType>(_ body: (IntegerBytes) throws(CryptoKitMetaError) -> ReturnType) throws(CryptoKitMetaError) -> ReturnType
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ASN1IntegerRepresentable {
    static var defaultIdentifier: ASN1.ASN1Identifier {
        .integer
    }

    internal init(asn1Encoded node: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws(CryptoKitMetaError) {
        guard node.identifier == identifier else {
            throw error(CryptoKitASN1Error.unexpectedFieldType)
        }

        guard case .primitive(var dataBytes) = node.content else {
            preconditionFailure("ASN.1 parser generated primitive node with constructed content")
        }

        // Zero bytes of integer is not an acceptable encoding.
        guard dataBytes.count > 0 else {
            throw error(CryptoKitASN1Error.invalidASN1IntegerEncoding)
        }

        // 8.3.2 If the contents octets of an integer value encoding consist of more than one octet, then the bits of the first octet and bit 8 of the second octet:
        //
        // a) shall not all be ones; and
        // b) shall not all be zero.
        //
        // NOTE – These rules ensure that an integer value is always encoded in the smallest possible number of octets.
        if let first = dataBytes.first, let second = dataBytes.dropFirst().first {
            if (first == 0xFF) && second.topBitSet ||
                (first == 0x00) && !second.topBitSet {
                throw error(CryptoKitASN1Error.invalidASN1IntegerEncoding)
            }
        }

        // If the type we're trying to decode is unsigned, and the top byte is zero, we should strip it.
        // If the top bit is set, however, this is an invalid conversion: the number needs to be positive!
        if !Self.isSigned, let first = dataBytes.first {
            if first == 0x00 {
                dataBytes = dataBytes.dropFirst()
            } else if first & 0x80 == 0x80 {
                throw error(CryptoKitASN1Error.invalidASN1IntegerEncoding)
            }
        }

        self = try Self(asn1IntegerBytes: dataBytes)
    }

    internal func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws(CryptoKitMetaError) {
        try coder.appendPrimitiveNode(identifier: identifier) { bytes throws(CryptoKitMetaError) in
            try self.withBigEndianIntegerBytes { integerBytes throws(CryptoKitMetaError) in
                // If the number of bytes is 0, we're encoding a zero. That actually _does_ require one byte.
                if integerBytes.count == 0 {
                    bytes.append(0)
                    return
                }

                // If self is unsigned and the first byte has the top bit set, we need to prepend a 0 byte.
                if !Self.isSigned, let topByte = integerBytes.first, topByte.topBitSet {
                    bytes.append(0)
                    bytes.append(contentsOf: integerBytes)
                } else {
                    // Either self is signed, or the top bit isn't set. Either way, trim to make sure the representation is minimal.
                    bytes.append(contentsOf: integerBytes.trimLeadingExcessBytes())
                }
            }
        }
    }
}

// MARK: - Auto-conformance for FixedWidthInteger with fixed width magnitude.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ASN1IntegerRepresentable where Self: FixedWidthInteger {
    init(asn1IntegerBytes bytes: ArraySlice<UInt8>) throws(CryptoKitMetaError) {
        // Defer to the FixedWidthInteger constructor.
        // There's a wrinkle here: if this is a signed integer, and the top bit of the data bytes was set,
        // then we need to 1-extend the bytes. This is because ASN.1 tries to delete redundant bytes that
        // are all 1.
        self = try Self(bigEndianBytes: bytes)

        if Self.isSigned, let first = bytes.first, first.topBitSet {
            for shift in stride(from: self.bitWidth - self.leadingZeroBitCount, to: self.bitWidth, by: 8) {
                self |= 0xFF << shift
            }
        }
    }

    func withBigEndianIntegerBytes<ReturnType>(_ body: (IntegerBytesCollection<Self>) throws(CryptoKitMetaError) -> ReturnType) throws(CryptoKitMetaError) -> ReturnType {
        return try body(IntegerBytesCollection(self))
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct IntegerBytesCollection<Integer: FixedWidthInteger> {
    private var integer: Integer

    init(_ integer: Integer) {
        self.integer = integer
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension IntegerBytesCollection: RandomAccessCollection {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    struct Index {
        fileprivate var byteNumber: Int

        fileprivate init(byteNumber: Int) {
            self.byteNumber = byteNumber
        }

        fileprivate var shift: Integer {
            // As byte number 0 is the end index, the byte number is one byte too large for the shift.
            return Integer((self.byteNumber - 1) * 8)
        }
    }

    var startIndex: Index {
        return Index(byteNumber: Int(self.integer.neededBytes))
    }

    var endIndex: Index {
        return Index(byteNumber: 0)
    }

    var count: Int {
        return Int(self.integer.neededBytes)
    }

    subscript(index: Index) -> UInt8 {
        // We perform the bitwise operations in magnitude space.
        let shifted = Integer.Magnitude(truncatingIfNeeded: self.integer) >> index.shift
        let masked = shifted & 0xFF
        return UInt8(masked)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension IntegerBytesCollection.Index: Equatable { }

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension IntegerBytesCollection.Index: Comparable {
    // Comparable here is backwards to the original ordering.
    static func <(lhs: Self, rhs: Self) -> Bool {
        return lhs.byteNumber > rhs.byteNumber
    }

    static func >(lhs: Self, rhs: Self) -> Bool {
        return lhs.byteNumber < rhs.byteNumber
    }

    static func <=(lhs: Self, rhs: Self) -> Bool {
        return lhs.byteNumber >= rhs.byteNumber
    }

    static func >=(lhs: Self, rhs: Self) -> Bool {
        return lhs.byteNumber <= rhs.byteNumber
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension IntegerBytesCollection.Index: Strideable {
    func advanced(by n: Int) -> IntegerBytesCollection<Integer>.Index {
        return IntegerBytesCollection.Index(byteNumber: self.byteNumber - n)
    }

    func distance(to other: IntegerBytesCollection<Integer>.Index) -> Int {
        // Remember that early indices have high byte numbers and later indices have low ones.
        return self.byteNumber - other.byteNumber
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Int8: ASN1IntegerRepresentable { }

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension UInt8: ASN1IntegerRepresentable { }

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Int16: ASN1IntegerRepresentable { }

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension UInt16: ASN1IntegerRepresentable { }

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Int32: ASN1IntegerRepresentable { }

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension UInt32: ASN1IntegerRepresentable { }

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Int64: ASN1IntegerRepresentable { }

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension UInt64: ASN1IntegerRepresentable { }

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Int: ASN1IntegerRepresentable { }

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension UInt: ASN1IntegerRepresentable { }

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension RandomAccessCollection where Element == UInt8 {
    fileprivate func trimLeadingExcessBytes() -> SubSequence {
        var slice = self[...]
        guard let first = slice.first else {
            // Easy case, empty.
            return slice
        }

        let wholeByte: UInt8

        switch first {
        case 0:
            wholeByte = 0
        case 0xFF:
            wholeByte = 0xFF
        default:
            // We're already fine, this is maximally compact. We need the whole thing.
            return slice
        }

        // We never trim this to less than one byte, as that's always the smallest representation.
        while slice.count > 1 {
            // If the first byte is equal to our original first byte, and the top bit
            // of the next byte is also equal to that, then we need to drop the byte and
            // go again.
            if slice.first != wholeByte {
                break
            }

            guard let second = slice.dropFirst().first else {
                preconditionFailure("Loop condition violated: must be at least two bytes left")
            }

            if second & 0x80 != wholeByte & 0x80 {
                // Different top bit, we need the leading byte.
                break
            }

            // Both the first byte and the top bit of the next are all zero or all 1, drop the leading
            // byte.
            slice = slice.dropFirst()
        }

        return slice
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension UInt8 {
    fileprivate var topBitSet: Bool {
        return (self & 0x80) != 0
    }
}

#endif // Linux or !SwiftPM
