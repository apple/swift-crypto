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

/// A wrapper around BoringSSL's EC_GROUP object that handles reference counting and
/// liveness.
@usableFromInline
class BoringSSLEllipticCurveGroup {
    /* private but usableFromInline */ @usableFromInline var _group: OpaquePointer

    @usableFromInline
    init(_ curve: CurveName) throws {
        guard let group = CCryptoBoringSSL_EC_GROUP_new_by_curve_name(curve.baseNID) else {
            throw CryptoKitError.internalBoringSSLError()
        }

        self._group = group
    }

    deinit {
        CCryptoBoringSSL_EC_GROUP_free(self._group)
    }
}

// MARK: - Helpers

extension BoringSSLEllipticCurveGroup {
    @usableFromInline
    var coordinateByteCount: Int {
        return (Int(CCryptoBoringSSL_EC_GROUP_get_degree(self._group)) + 7) / 8
    }

    @usableFromInline
    func makeUnsafeOwnedECKey() throws -> OpaquePointer {
        guard let key = CCryptoBoringSSL_EC_KEY_new(),
            CCryptoBoringSSL_EC_KEY_set_group(key, self._group) == 1 else {
            throw CryptoKitError.internalBoringSSLError()
        }

        return key
    }

    @inlinable
    func withUnsafeGroupPointer<T>(_ body: (OpaquePointer) throws -> T) rethrows -> T {
        return try body(self._group)
    }

    @usableFromInline
    var order: ArbitraryPrecisionInteger {
        // Groups must have an order.
        let baseOrder = CCryptoBoringSSL_EC_GROUP_get0_order(self._group)!
        return try! ArbitraryPrecisionInteger(copying: baseOrder)
    }

    /// An elliptic curve can be represented in a Weierstrass form: `y² = x³ + ax + b`. This
    /// property provides the values of a and b on the curve.
    @usableFromInline
    var weierstrassCoefficients: (field: ArbitraryPrecisionInteger, a: ArbitraryPrecisionInteger, b: ArbitraryPrecisionInteger) {
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

extension BoringSSLEllipticCurveGroup {
    @usableFromInline
    enum CurveName {
        case p256
        case p384
        case p521
    }
}

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
