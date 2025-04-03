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
@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims

import protocol Foundation.ContiguousBytes
import struct Foundation.Data

/// A wrapper around BoringSSL's EC_POINT with some lifetime management.
@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
package final class EllipticCurvePoint {
    @usableFromInline var _basePoint: OpaquePointer

    @usableFromInline
    package init(copying pointer: OpaquePointer, on group: BoringSSLEllipticCurveGroup) throws {
        self._basePoint = try group.withUnsafeGroupPointer { groupPtr in
            guard let pointPtr = CCryptoBoringSSL_EC_POINT_dup(pointer, groupPtr) else {
                throw CryptoBoringWrapperError.internalBoringSSLError()
            }
            return pointPtr
        }
    }

    @usableFromInline
    package convenience init(
        copying other: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup
    )
        throws
    {
        try self.init(copying: other._basePoint, on: group)
    }

    @usableFromInline
    package init(_pointAtInfinityOn group: BoringSSLEllipticCurveGroup) throws {
        self._basePoint = try group.withUnsafeGroupPointer { groupPtr in
            guard let pointPtr = CCryptoBoringSSL_EC_POINT_new(groupPtr) else {
                throw CryptoBoringWrapperError.internalBoringSSLError()
            }
            return pointPtr
        }
    }

    @usableFromInline
    package convenience init(
        multiplying scalar: ArbitraryPrecisionInteger,
        on group: BoringSSLEllipticCurveGroup
    ) throws {
        try self.init(_pointAtInfinityOn: group)
        try group.withUnsafeGroupPointer { groupPtr in
            try scalar.withUnsafeBignumPointer { scalarPtr in
                guard
                    CCryptoBoringSSL_EC_POINT_mul(groupPtr, self._basePoint, scalarPtr, nil, nil, nil) == 1
                else {
                    throw CryptoBoringWrapperError.internalBoringSSLError()
                }
            }
        }
    }

    deinit {
        CCryptoBoringSSL_EC_POINT_free(self._basePoint)
    }

    @usableFromInline
    package func multiply(
        by rhs: ArbitraryPrecisionInteger,
        on group: BoringSSLEllipticCurveGroup
    )
        throws
    {
        try self.withPointPointer { selfPtr in
            try rhs.withUnsafeBignumPointer { rhsPtr in
                try group.withUnsafeGroupPointer { groupPtr in
                    guard CCryptoBoringSSL_EC_POINT_mul(groupPtr, selfPtr, nil, selfPtr, rhsPtr, nil) != 0
                    else {
                        throw CryptoBoringWrapperError.internalBoringSSLError()
                    }
                }
            }
        }
    }

    @usableFromInline
    package convenience init(
        multiplying lhs: EllipticCurvePoint,
        by rhs: ArbitraryPrecisionInteger,
        on group: BoringSSLEllipticCurveGroup
    ) throws {
        try self.init(copying: lhs, on: group)
        try self.multiply(by: rhs, on: group)
    }

    @usableFromInline
    package func multiplying(
        by rhs: ArbitraryPrecisionInteger,
        on group: BoringSSLEllipticCurveGroup
    )
        throws -> EllipticCurvePoint
    {
        try EllipticCurvePoint(multiplying: self, by: rhs, on: group)
    }

    @usableFromInline
    package static func multiplying(
        _ lhs: EllipticCurvePoint,
        by rhs: ArbitraryPrecisionInteger,
        on group: BoringSSLEllipticCurveGroup
    ) throws -> EllipticCurvePoint {
        try EllipticCurvePoint(multiplying: lhs, by: rhs, on: group)
    }

    @usableFromInline
    package func add(_ rhs: EllipticCurvePoint, on group: BoringSSLEllipticCurveGroup) throws {
        try self.withPointPointer { selfPtr in
            try group.withUnsafeGroupPointer { groupPtr in
                try rhs.withPointPointer { rhsPtr in
                    guard CCryptoBoringSSL_EC_POINT_add(groupPtr, selfPtr, selfPtr, rhsPtr, nil) != 0 else {
                        throw CryptoBoringWrapperError.internalBoringSSLError()
                    }
                }
            }
        }
    }

    @usableFromInline
    package convenience init(
        adding lhs: EllipticCurvePoint,
        _ rhs: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup
    ) throws {
        try self.init(copying: lhs, on: group)
        try self.add(rhs, on: group)
    }

    @usableFromInline
    package func adding(
        _ rhs: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup
    ) throws
        -> EllipticCurvePoint
    {
        try EllipticCurvePoint(adding: self, rhs, on: group)
    }

    @usableFromInline
    package static func adding(
        _ lhs: EllipticCurvePoint,
        _ rhs: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup
    ) throws -> EllipticCurvePoint {
        try EllipticCurvePoint(adding: lhs, rhs, on: group)
    }

    @usableFromInline
    package func invert(on group: BoringSSLEllipticCurveGroup) throws {
        try self.withPointPointer { selfPtr in
            try group.withUnsafeGroupPointer { groupPtr in
                guard CCryptoBoringSSL_EC_POINT_invert(groupPtr, selfPtr, nil) != 0 else {
                    throw CryptoBoringWrapperError.internalBoringSSLError()
                }
            }
        }
    }

    @usableFromInline
    package convenience init(
        inverting point: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup
    ) throws {
        try self.init(copying: point, on: group)
        try self.invert(on: group)
    }

    @usableFromInline
    package func inverting(on group: BoringSSLEllipticCurveGroup) throws -> EllipticCurvePoint {
        try EllipticCurvePoint(inverting: self, on: group)
    }

    @usableFromInline
    package static func inverting(
        _ point: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup
    )
        throws -> EllipticCurvePoint
    {
        try EllipticCurvePoint(inverting: point, on: group)
    }

    @usableFromInline
    package func subtract(_ rhs: EllipticCurvePoint, on group: BoringSSLEllipticCurveGroup) throws {
        try self.add(rhs.inverting(on: group), on: group)
    }

    @usableFromInline
    package convenience init(
        subtracting rhs: EllipticCurvePoint,
        from lhs: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup
    ) throws {
        try self.init(copying: lhs, on: group)
        try self.subtract(rhs, on: group)
    }

    @usableFromInline
    package func subtracting(
        _ rhs: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup
    ) throws
        -> EllipticCurvePoint
    {
        try EllipticCurvePoint(subtracting: rhs, from: self, on: group)
    }

    @usableFromInline
    package static func subtracting(
        _ rhs: EllipticCurvePoint,
        from lhs: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup
    ) throws -> EllipticCurvePoint {
        try EllipticCurvePoint(subtracting: rhs, from: lhs, on: group)
    }

    @usableFromInline
    package convenience init<MessageBytes: ContiguousBytes, DSTBytes: ContiguousBytes>(
        hashing msg: MessageBytes,
        to group: BoringSSLEllipticCurveGroup,
        domainSeparationTag: DSTBytes
    ) throws {
        let hashToCurveFunction =
            switch group.curveName {
            case .p256: CCryptoBoringSSLShims_EC_hash_to_curve_p256_xmd_sha256_sswu
            case .p384: CCryptoBoringSSLShims_EC_hash_to_curve_p384_xmd_sha384_sswu
            case .p521: throw CryptoBoringWrapperError.invalidParameter  // BoringSSL has no P521 hash_to_curve API.
            case .none: throw CryptoBoringWrapperError.internalBoringSSLError()
            }

        try self.init(_pointAtInfinityOn: group)
        try msg.withUnsafeBytes { msgPtr in
            try group.withUnsafeGroupPointer { groupPtr in
                try domainSeparationTag.withUnsafeBytes { dstPtr in
                    guard
                        hashToCurveFunction(
                            groupPtr,
                            self._basePoint,
                            dstPtr.baseAddress,
                            dstPtr.count,
                            msgPtr.baseAddress,
                            msgPtr.count
                        ) == 1
                    else { throw CryptoBoringWrapperError.internalBoringSSLError() }
                }
            }
        }
    }

    @usableFromInline
    package func isEqual(to rhs: EllipticCurvePoint, on group: BoringSSLEllipticCurveGroup) -> Bool {
        self.withPointPointer { selfPtr in
            group.withUnsafeGroupPointer { groupPtr in
                rhs.withPointPointer { rhsPtr in
                    switch CCryptoBoringSSL_EC_POINT_cmp(groupPtr, selfPtr, rhsPtr, nil) {
                    case 0: return true
                    case 1: return false
                    default:
                        // EC_POINT_cmp returns an error when comparing points on different groups.
                        // We treat that as not equal, so we'll just clear the error and return false.
                        CCryptoBoringSSL_ERR_clear_error()
                        return false
                    }
                }
            }
        }
    }

    @usableFromInline
    package convenience init<Bytes: ContiguousBytes>(
        x962Representation bytes: Bytes,
        on group: BoringSSLEllipticCurveGroup
    ) throws {
        try self.init(_pointAtInfinityOn: group)
        guard
            group.withUnsafeGroupPointer({ groupPtr in
                bytes.withUnsafeBytes { dataPtr in
                    CCryptoBoringSSL_EC_POINT_oct2point(
                        groupPtr,
                        self._basePoint,
                        dataPtr.baseAddress,
                        dataPtr.count,
                        nil
                    )
                }
            }) == 1
        else {
            throw CryptoBoringWrapperError.invalidParameter
        }
    }

    @usableFromInline
    package func x962RepresentationByteCount(
        compressed: Bool,
        on group: BoringSSLEllipticCurveGroup
    )
        throws -> Int
    {
        let numBytesNeeded = group.withUnsafeGroupPointer { groupPtr in
            CCryptoBoringSSL_EC_POINT_point2oct(
                groupPtr,
                self._basePoint,
                compressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED,
                nil,
                0,
                nil
            )
        }
        guard numBytesNeeded != 0 else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }
        return numBytesNeeded
    }

    @usableFromInline
    package func x962Representation(
        compressed: Bool,
        on group: BoringSSLEllipticCurveGroup
    ) throws
        -> Data
    {
        let numBytesNeeded = try self.x962RepresentationByteCount(compressed: compressed, on: group)

        var buf = Data(repeating: 0, count: numBytesNeeded)

        let numBytesWritten = group.withUnsafeGroupPointer { groupPtr in
            buf.withUnsafeMutableBytes { bufPtr in
                CCryptoBoringSSLShims_EC_POINT_point2oct(
                    groupPtr,
                    self._basePoint,
                    compressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED,
                    bufPtr.baseAddress,
                    numBytesNeeded,
                    nil
                )
            }
        }
        guard numBytesWritten == numBytesNeeded else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }

        return buf
    }
}

// MARK: - Helpers

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension EllipticCurvePoint {
    @inlinable
    package func withPointPointer<T>(_ body: (OpaquePointer) throws -> T) rethrows -> T {
        try body(self._basePoint)
    }

    @usableFromInline
    package func affineCoordinates(
        group: BoringSSLEllipticCurveGroup
    ) throws -> (
        x: ArbitraryPrecisionInteger, y: ArbitraryPrecisionInteger
    ) {
        var x = ArbitraryPrecisionInteger()
        var y = ArbitraryPrecisionInteger()

        try x.withUnsafeMutableBignumPointer { xPtr in
            try y.withUnsafeMutableBignumPointer { yPtr in
                try group.withUnsafeGroupPointer { groupPtr in
                    guard
                        CCryptoBoringSSL_EC_POINT_get_affine_coordinates_GFp(
                            groupPtr,
                            self._basePoint,
                            xPtr,
                            yPtr,
                            nil
                        ) != 0
                    else {
                        throw CryptoBoringWrapperError.internalBoringSSLError()
                    }
                }
            }
        }

        return (x: x, y: y)
    }
}
