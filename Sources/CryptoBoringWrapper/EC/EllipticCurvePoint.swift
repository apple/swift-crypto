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

/// A wrapper around BoringSSL's EC_POINT with some lifetime management and value semantics.
@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
package struct EllipticCurvePoint: @unchecked Sendable {
    @usableFromInline
    var backing: Backing

    @usableFromInline
    package init(copying pointer: OpaquePointer, on group: BoringSSLEllipticCurveGroup) throws {
        self.backing = try .init(copying: pointer, on: group)
    }

    @usableFromInline
    package init(_pointAtInfinityOn group: BoringSSLEllipticCurveGroup) throws {
        self.backing = try .init(_pointAtInfinityOn: group)
    }

    @usableFromInline
    package init(_generatorOf groupPtr: OpaquePointer) throws {
        self.backing = try .init(_generatorOf: groupPtr)
    }

    @usableFromInline
    package init(
        multiplying scalar: ArbitraryPrecisionInteger,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws {
        self.backing = try .init(multiplying: scalar, on: group, context: context)
    }

    @usableFromInline
    package mutating func multiply(
        by rhs: ArbitraryPrecisionInteger,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws {
        try self.cowIfNeeded(on: group)
        try self.backing.multiply(by: rhs, on: group, context: context)
    }

    @usableFromInline
    package init(
        multiplying lhs: EllipticCurvePoint,
        by rhs: ArbitraryPrecisionInteger,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws {
        self = lhs
        try self.multiply(by: rhs, on: group, context: context)
    }

    // This enhancement can only be present on 6.1 or later because of the
    // absence of https://github.com/swiftlang/swift/pull/76186 in older
    // compilers.
    #if compiler(>=6.1)
    @usableFromInline
    package consuming func multiplying(
        by rhs: ArbitraryPrecisionInteger,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws -> EllipticCurvePoint {
        try self.multiply(by: rhs, on: group, context: context)
        return self
    }
    #else
    @usableFromInline
    package func multiplying(
        by rhs: ArbitraryPrecisionInteger,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws -> EllipticCurvePoint {
        var `self` = self
        try self.multiply(by: rhs, on: group, context: context)
        return self
    }
    #endif

    @usableFromInline
    package static func multiplying(
        _ lhs: consuming EllipticCurvePoint,
        by rhs: ArbitraryPrecisionInteger,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws -> EllipticCurvePoint {
        try lhs.multiplying(by: rhs, on: group, context: context)
    }

    @usableFromInline
    package mutating func add(
        _ rhs: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws {
        try self.cowIfNeeded(on: group)
        try self.backing.add(rhs, on: group, context: context)
    }

    @usableFromInline
    package init(
        adding lhs: EllipticCurvePoint,
        _ rhs: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws {
        self = lhs
        try self.add(rhs, on: group, context: context)
    }

    // This enhancement can only be present on 6.1 or later because of the
    // absence of https://github.com/swiftlang/swift/pull/76186 in older
    // compilers.
    #if compiler(>=6.1)
    @usableFromInline
    package consuming func adding(
        _ rhs: consuming EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws -> EllipticCurvePoint {
        try self.add(rhs, on: group, context: context)
        return self
    }
    #else
    @usableFromInline
    package func adding(
        _ rhs: consuming EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws -> EllipticCurvePoint {
        var `self` = self
        try self.add(rhs, on: group, context: context)
        return self
    }
    #endif

    // This enhancement can only be present on 6.1 or later because of the
    // absence of https://github.com/swiftlang/swift/pull/76186 in older
    // compilers.
    #if compiler(>=6.1)
    @usableFromInline
    package static func adding(
        _ lhs: consuming EllipticCurvePoint,
        _ rhs: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws -> EllipticCurvePoint {
        try lhs.add(rhs, on: group, context: context)
        return lhs
    }
    #else
    @usableFromInline
    package static func adding(
        _ lhs: EllipticCurvePoint,
        _ rhs: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws -> EllipticCurvePoint {
        var lhs = lhs
        try lhs.add(rhs, on: group, context: context)
        return lhs
    }
    #endif

    @usableFromInline
    package mutating func invert(
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws {
        try self.cowIfNeeded(on: group)
        try self.backing.invert(on: group, context: context)
    }

    @usableFromInline
    package init(
        inverting point: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws {
        self = point
        try self.invert(on: group, context: context)
    }

    // This enhancement can only be present on 6.1 or later because of the
    // absence of https://github.com/swiftlang/swift/pull/76186 in older
    // compilers.
    #if compiler(>=6.1)
    @usableFromInline
    package consuming func inverting(
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws -> EllipticCurvePoint {
        try self.invert(on: group, context: context)
        return self
    }
    #else
    @usableFromInline
    package func inverting(
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws -> EllipticCurvePoint {
        var `self` = self
        try self.invert(on: group, context: context)
        return self
    }
    #endif

    // This enhancement can only be present on 6.1 or later because of the
    // absence of https://github.com/swiftlang/swift/pull/76186 in older
    // compilers.
    #if compiler(>=6.1)
    @usableFromInline
    package static func inverting(
        _ point: consuming EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws -> EllipticCurvePoint {
        try point.invert(on: group, context: context)
        return point
    }
    #else
    @usableFromInline
    package static func inverting(
        _ point: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws -> EllipticCurvePoint {
        var point = point
        try point.invert(on: group, context: context)
        return point
    }
    #endif

    @usableFromInline
    package mutating func subtract(
        _ rhs: consuming EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws {
        try self.cowIfNeeded(on: group)
        try self.add(rhs.inverting(on: group), on: group, context: context)
    }

    @usableFromInline
    package init(
        subtracting rhs: consuming EllipticCurvePoint,
        from lhs: consuming EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws {
        self = lhs
        try self.subtract(rhs, on: group, context: context)
    }

    // This enhancement can only be present on 6.1 or later because of the
    // absence of https://github.com/swiftlang/swift/pull/76186 in older
    // compilers.
    #if compiler(>=6.1)
    @usableFromInline
    package consuming func subtracting(
        _ rhs: consuming EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws -> EllipticCurvePoint {
        try self.subtract(rhs, on: group, context: context)
        return self
    }
    #else
    @usableFromInline
    package func subtracting(
        _ rhs: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws -> EllipticCurvePoint {
        var `self` = self
        try self.subtract(rhs, on: group, context: context)
        return self
    }
    #endif

    // This enhancement can only be present on 6.1 or later because of the
    // absence of https://github.com/swiftlang/swift/pull/76186 in older
    // compilers.
    #if compiler(>=6.1)
    @usableFromInline
    package static func subtracting(
        _ rhs: consuming EllipticCurvePoint,
        from lhs: consuming EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws -> EllipticCurvePoint {
        try lhs.subtract(rhs, on: group, context: context)
        return lhs
    }
    #else
    @usableFromInline
    package static func subtracting(
        _ rhs: EllipticCurvePoint,
        from lhs: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws -> EllipticCurvePoint {
        var lhs = lhs
        try lhs.subtract(rhs, on: group, context: context)
        return lhs
    }
    #endif

    @usableFromInline
    package init<MessageBytes: ContiguousBytes, DSTBytes: ContiguousBytes>(
        hashing msg: MessageBytes,
        to group: BoringSSLEllipticCurveGroup,
        domainSeparationTag: DSTBytes
    ) throws {
        self.backing = try .init(hashing: msg, to: group, domainSeparationTag: domainSeparationTag)
    }

    @usableFromInline
    package func isEqual(
        to rhs: EllipticCurvePoint,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) -> Bool {
        self.backing.isEqual(to: rhs, on: group, context: context)
    }

    @usableFromInline
    package init<Bytes: ContiguousBytes>(
        x962Representation bytes: Bytes,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws {
        self.backing = try .init(x962Representation: bytes, on: group, context: context)
    }

    @usableFromInline
    package func x962Representation(
        compressed: Bool,
        on group: BoringSSLEllipticCurveGroup,
        context: FiniteFieldArithmeticContext? = nil
    ) throws -> Data {
        try self.backing.x962Representation(compressed: compressed, on: group, context: context)
    }

    private mutating func cowIfNeeded(on group: BoringSSLEllipticCurveGroup) throws {
        if !isKnownUniquelyReferenced(&self.backing) {
            self.backing = try .init(copying: self.backing, on: group)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension EllipticCurvePoint {
    @usableFromInline
    final class Backing {
        @usableFromInline
        let _basePoint: OpaquePointer

        fileprivate init(copying pointer: OpaquePointer, on group: BoringSSLEllipticCurveGroup) throws {
            self._basePoint = try group.withUnsafeGroupPointer { groupPtr in
                guard let pointPtr = CCryptoBoringSSL_EC_POINT_dup(pointer, groupPtr) else {
                    throw CryptoBoringWrapperError.internalBoringSSLError()
                }
                return pointPtr
            }
        }

        fileprivate convenience init(
            copying other: Backing,
            on group: BoringSSLEllipticCurveGroup
        )
            throws
        {
            try self.init(copying: other._basePoint, on: group)
        }

        fileprivate init(_pointAtInfinityOn group: BoringSSLEllipticCurveGroup) throws {
            self._basePoint = try group.withUnsafeGroupPointer { groupPtr in
                guard let pointPtr = CCryptoBoringSSL_EC_POINT_new(groupPtr) else {
                    throw CryptoBoringWrapperError.internalBoringSSLError()
                }
                return pointPtr
            }
        }

        fileprivate init(_generatorOf groupPtr: OpaquePointer) throws {
            guard
                let generatorPtr = CCryptoBoringSSL_EC_GROUP_get0_generator(groupPtr),
                let pointPtr = CCryptoBoringSSL_EC_POINT_dup(generatorPtr, groupPtr)
            else {
                throw CryptoBoringWrapperError.internalBoringSSLError()
            }
            self._basePoint = pointPtr
        }

        fileprivate convenience init(
            multiplying scalar: ArbitraryPrecisionInteger,
            on group: BoringSSLEllipticCurveGroup,
            context: FiniteFieldArithmeticContext? = nil
        ) throws {
            try self.init(_pointAtInfinityOn: group)
            try group.withUnsafeGroupPointer { groupPtr in
                try scalar.withUnsafeBignumPointer { scalarPtr in
                    guard
                        CCryptoBoringSSL_EC_POINT_mul(groupPtr, self._basePoint, scalarPtr, nil, nil, context?.bnCtx)
                            == 1
                    else {
                        throw CryptoBoringWrapperError.internalBoringSSLError()
                    }
                }
            }
        }

        deinit {
            CCryptoBoringSSL_EC_POINT_free(self._basePoint)
        }

        fileprivate func multiply(
            by rhs: ArbitraryPrecisionInteger,
            on group: BoringSSLEllipticCurveGroup,
            context: FiniteFieldArithmeticContext? = nil
        ) throws {
            try self.withPointPointer { selfPtr in
                try rhs.withUnsafeBignumPointer { rhsPtr in
                    try group.withUnsafeGroupPointer { groupPtr in
                        guard
                            CCryptoBoringSSL_EC_POINT_mul(groupPtr, selfPtr, nil, selfPtr, rhsPtr, context?.bnCtx) != 0
                        else {
                            throw CryptoBoringWrapperError.internalBoringSSLError()
                        }
                    }
                }
            }
        }

        fileprivate func add(
            _ rhs: EllipticCurvePoint,
            on group: BoringSSLEllipticCurveGroup,
            context: FiniteFieldArithmeticContext? = nil
        ) throws {
            try self.withPointPointer { selfPtr in
                try group.withUnsafeGroupPointer { groupPtr in
                    try rhs.withPointPointer { rhsPtr in
                        guard CCryptoBoringSSL_EC_POINT_add(groupPtr, selfPtr, selfPtr, rhsPtr, context?.bnCtx) != 0
                        else {
                            throw CryptoBoringWrapperError.internalBoringSSLError()
                        }
                    }
                }
            }
        }

        internal func invert(on group: BoringSSLEllipticCurveGroup, context: FiniteFieldArithmeticContext? = nil) throws
        {
            try self.withPointPointer { selfPtr in
                try group.withUnsafeGroupPointer { groupPtr in
                    guard CCryptoBoringSSL_EC_POINT_invert(groupPtr, selfPtr, context?.bnCtx) != 0 else {
                        throw CryptoBoringWrapperError.internalBoringSSLError()
                    }
                }
            }
        }

        fileprivate convenience init<MessageBytes: ContiguousBytes, DSTBytes: ContiguousBytes>(
            hashing msg: MessageBytes,
            to group: BoringSSLEllipticCurveGroup,
            domainSeparationTag: DSTBytes
        ) throws {
            let hashToCurveFunction =
                switch group.curveName {
                case .p256: CCryptoBoringSSLShims_EC_hash_to_curve_p256_xmd_sha256_sswu
                case .p384: CCryptoBoringSSLShims_EC_hash_to_curve_p384_xmd_sha384_sswu
                // BoringSSL has no P521 hash_to_curve API.
                case .p521: throw CryptoBoringWrapperError.invalidParameter
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

        fileprivate func isEqual(
            to rhs: EllipticCurvePoint,
            on group: BoringSSLEllipticCurveGroup,
            context: FiniteFieldArithmeticContext? = nil
        ) -> Bool {
            self.withPointPointer { selfPtr in
                group.withUnsafeGroupPointer { groupPtr in
                    rhs.withPointPointer { rhsPtr in
                        switch CCryptoBoringSSL_EC_POINT_cmp(groupPtr, selfPtr, rhsPtr, context?.bnCtx) {
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

        fileprivate convenience init<Bytes: ContiguousBytes>(
            x962Representation bytes: Bytes,
            on group: BoringSSLEllipticCurveGroup,
            context: FiniteFieldArithmeticContext? = nil
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
                            context?.bnCtx
                        )
                    }
                }) == 1
            else {
                throw CryptoBoringWrapperError.invalidParameter
            }
        }

        private func x962RepresentationByteCount(
            compressed: Bool,
            on group: BoringSSLEllipticCurveGroup,
            context: FiniteFieldArithmeticContext? = nil
        ) throws -> Int {
            let numBytesNeeded = group.withUnsafeGroupPointer { groupPtr in
                CCryptoBoringSSL_EC_POINT_point2oct(
                    groupPtr,
                    self._basePoint,
                    compressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED,
                    nil,
                    0,
                    context?.bnCtx
                )
            }
            guard numBytesNeeded != 0 else {
                throw CryptoBoringWrapperError.internalBoringSSLError()
            }
            return numBytesNeeded
        }

        fileprivate func x962Representation(
            compressed: Bool,
            on group: BoringSSLEllipticCurveGroup,
            context: FiniteFieldArithmeticContext? = nil
        ) throws -> Data {
            let numBytesNeeded = try self.x962RepresentationByteCount(
                compressed: compressed,
                on: group,
                context: context
            )

            var buf = Data(repeating: 0, count: numBytesNeeded)

            let numBytesWritten = group.withUnsafeGroupPointer { groupPtr in
                buf.withUnsafeMutableBytes { bufPtr in
                    CCryptoBoringSSLShims_EC_POINT_point2oct(
                        groupPtr,
                        self._basePoint,
                        compressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED,
                        bufPtr.baseAddress,
                        numBytesNeeded,
                        context?.bnCtx
                    )
                }
            }
            guard numBytesWritten == numBytesNeeded else {
                throw CryptoBoringWrapperError.internalBoringSSLError()
            }

            return buf
        }
    }
}

// MARK: - Helpers

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension EllipticCurvePoint.Backing {
    @inlinable
    package func withPointPointer<T>(_ body: (OpaquePointer) throws -> T) rethrows -> T {
        try body(self._basePoint)
    }

    fileprivate func affineCoordinates(
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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension EllipticCurvePoint {
    @inlinable
    package func withPointPointer<T>(_ body: (OpaquePointer) throws -> T) rethrows -> T {
        try self.backing.withPointPointer(body)
    }

    @usableFromInline
    package func affineCoordinates(
        group: BoringSSLEllipticCurveGroup
    ) throws -> (
        x: ArbitraryPrecisionInteger, y: ArbitraryPrecisionInteger
    ) {
        try self.backing.affineCoordinates(group: group)
    }
}
