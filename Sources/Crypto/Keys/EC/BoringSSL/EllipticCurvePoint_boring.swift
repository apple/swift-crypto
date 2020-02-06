//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
@_implementationOnly import CCryptoBoringSSL

/// A wrapper around BoringSSL's EC_POINT with some lifetime management.
@usableFromInline
class EllipticCurvePoint {
    /* private but @usableFromInline */ @usableFromInline var _basePoint: OpaquePointer

    @usableFromInline
    init(multiplying scalar: ArbitraryPrecisionInteger, on group: BoringSSLEllipticCurveGroup) throws {
        self._basePoint = try group.withUnsafeGroupPointer { groupPtr in
            guard let basePoint = CCryptoBoringSSL_EC_POINT_new(groupPtr) else {
                throw CryptoKitError.internalBoringSSLError()
            }
            return basePoint
        }

        try group.withUnsafeGroupPointer { groupPtr in
            try scalar.withUnsafeBignumPointer { bigNumPtr in
                guard CCryptoBoringSSL_EC_POINT_mul(groupPtr, self._basePoint, bigNumPtr, nil, nil, nil) != 0 else {
                    throw CryptoKitError.internalBoringSSLError()
                }
            }
        }
    }

    init(copying pointer: OpaquePointer, on group: BoringSSLEllipticCurveGroup) throws {
        self._basePoint = try group.withUnsafeGroupPointer { groupPtr in
            guard let basePoint = CCryptoBoringSSL_EC_POINT_dup(pointer, groupPtr) else {
                throw CryptoKitError.internalBoringSSLError()
            }
            return basePoint
        }
    }

    deinit {
        CCryptoBoringSSL_EC_POINT_free(self._basePoint)
    }
}

// MARK: - Helpers

extension EllipticCurvePoint {
    @inlinable
    func withPointPointer<T>(_ body: (OpaquePointer) throws -> T) rethrows -> T {
        return try body(self._basePoint)
    }

    @usableFromInline
    func affineCoordinates(group: BoringSSLEllipticCurveGroup) throws -> (x: ArbitraryPrecisionInteger, y: ArbitraryPrecisionInteger) {
        var x = ArbitraryPrecisionInteger()
        var y = ArbitraryPrecisionInteger()

        try x.withUnsafeMutableBignumPointer { xPtr in
            try y.withUnsafeMutableBignumPointer { yPtr in
                try group.withUnsafeGroupPointer { groupPtr in
                    guard CCryptoBoringSSL_EC_POINT_get_affine_coordinates_GFp(groupPtr, self._basePoint, xPtr, yPtr, nil) != 0 else {
                        throw CryptoKitError.internalBoringSSLError()
                    }
                }
            }
        }

        return (x: x, y: y)
    }
}
