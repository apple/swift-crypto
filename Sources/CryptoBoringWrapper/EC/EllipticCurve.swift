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

/// A wrapper around BoringSSL's EC_GROUP object that handles reference counting and
/// liveness.
@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
package final class BoringSSLEllipticCurveGroup: @unchecked Sendable {
    @usableFromInline var _group: OpaquePointer

    @usableFromInline package let order: ArbitraryPrecisionInteger

    @usableFromInline package let generator: EllipticCurvePoint

    @usableFromInline
    package init(_ curve: CurveName) throws {
        guard let group = CCryptoBoringSSL_EC_GROUP_new_by_curve_name(curve.baseNID) else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }

        self._group = group

        let baseOrder = CCryptoBoringSSL_EC_GROUP_get0_order(self._group)!
        self.order = try! ArbitraryPrecisionInteger(copying: baseOrder)

        self.generator = try EllipticCurvePoint(_generatorOf: self._group)
    }

    deinit {
        CCryptoBoringSSL_EC_GROUP_free(self._group)
    }
}

// MARK: - Helpers

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLEllipticCurveGroup {
    @usableFromInline
    package var coordinateByteCount: Int {
        (Int(CCryptoBoringSSL_EC_GROUP_get_degree(self._group)) + 7) / 8
    }

    @usableFromInline
    package func makeUnsafeOwnedECKey() throws -> OpaquePointer {
        guard let key = CCryptoBoringSSL_EC_KEY_new(),
            CCryptoBoringSSL_EC_KEY_set_group(key, self._group) == 1
        else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }

        return key
    }

    @usableFromInline
    package func makeUnsafeOwnedECPoint() throws -> OpaquePointer {
        guard let point = CCryptoBoringSSL_EC_POINT_new(self._group) else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }

        return point
    }

    @inlinable
    package func withUnsafeGroupPointer<T>(_ body: (OpaquePointer) throws -> T) rethrows -> T {
        try body(self._group)
    }

    /// An elliptic curve can be represented in a Weierstrass form: `y² = x³ + ax + b`. This
    /// property provides the values of a and b on the curve.
    @usableFromInline
    package var weierstrassCoefficients:
        (field: ArbitraryPrecisionInteger, a: ArbitraryPrecisionInteger, b: ArbitraryPrecisionInteger)
    {
        var field = ArbitraryPrecisionInteger()
        var a = ArbitraryPrecisionInteger()
        var b = ArbitraryPrecisionInteger()

        let rc = field.withUnsafeMutableBignumPointer { fieldPtr in
            a.withUnsafeMutableBignumPointer { aPtr in
                b.withUnsafeMutableBignumPointer { bPtr in
                    CCryptoBoringSSL_EC_GROUP_get_curve_GFp(self._group, fieldPtr, aPtr, bPtr, nil)
                }
            }
        }
        precondition(rc == 1, "Unable to extract curve weierstrass parameters")

        return (field: field, a: a, b: b)
    }
}

// MARK: - CurveName

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLEllipticCurveGroup {
    @usableFromInline
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    package enum CurveName {
        case p256
        case p384
        case p521
    }

    @usableFromInline
    var curveName: CurveName? {
        switch CCryptoBoringSSL_EC_GROUP_get_curve_name(self._group) {
        case NID_X9_62_prime256v1:
            return .p256
        case NID_secp384r1:
            return .p384
        case NID_secp521r1:
            return .p521
        default:
            return nil
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLEllipticCurveGroup.CurveName {
    @usableFromInline
    var baseNID: CInt {
        switch self {
        case .p256:
            return NID_X9_62_prime256v1
        case .p384:
            return NID_secp384r1
        case .p521:
            return NID_secp521r1
        }
    }
}
