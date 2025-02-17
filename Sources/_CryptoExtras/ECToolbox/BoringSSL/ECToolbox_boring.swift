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
import Crypto
import CryptoBoringWrapper

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// NOTE: This protocol is different from `Crypto.OpenSSLSupportedNISTCurve` module and has additional requirements to
/// support ECToolbox. It is (re-)defined here because its counterpart in the Crypto module is only conditionally
/// compiled on _non-Darwin_ platforms, but we implement ECToolbox on both Darwin and non-Darwin platforms.
@usableFromInline
protocol OpenSSLSupportedNISTCurve {
    associatedtype H: HashFunction

    @inlinable
    static var group: BoringSSLEllipticCurveGroup { get }

    // TODO: we could use EC_GROUP_get_cofactor for this and drop this requirement.
    @inlinable
    static var cofactor: Int { get }

    @inlinable
    static var orderByteCount: Int { get }

    @inlinable
    static var compressedx962PointByteCount: Int { get }

    // TODO: could this be moved to the group or to the HashFunction?
    @inlinable
    static var hashToFieldByteCount: Int { get }
}

/// NOTE: This conformance applies to this type from the Crypto module even if it comes from the SDK.
extension P256: OpenSSLSupportedNISTCurve {
    @usableFromInline
    typealias H = SHA256

    @inlinable
    static var group: BoringSSLEllipticCurveGroup { try! BoringSSLEllipticCurveGroup(.p256) }

    @inlinable
    static var cofactor: Int { 1 }

    @inlinable
    static var orderByteCount: Int { 32 }

    @inlinable
    static var compressedx962PointByteCount: Int { 33 }

    @inlinable
    static var hashToFieldByteCount: Int { 48 }
}

/// NOTE: This conformance applies to this type from the Crypto module even if it comes from the SDK.
extension P384: OpenSSLSupportedNISTCurve {
    @usableFromInline
    typealias H = SHA384

    @inlinable
    static var group: BoringSSLEllipticCurveGroup { try! BoringSSLEllipticCurveGroup(.p384) }

    @inlinable
    static var cofactor: Int { 1 }

    @inlinable
    static var orderByteCount: Int { 48 }

    @inlinable
    static var compressedx962PointByteCount: Int { 49 }

    @inlinable
    static var hashToFieldByteCount: Int { 72 }
}

/// NOTE: This conformance applies to this type from the Crypto module even if it comes from the SDK.
extension P521: OpenSSLSupportedNISTCurve {
    @usableFromInline
    typealias H = SHA512

    @inlinable
    static var group: BoringSSLEllipticCurveGroup { try! BoringSSLEllipticCurveGroup(.p521) }

    @inlinable
    static var cofactor: Int { 1 }

    @inlinable
    static var orderByteCount: Int { 66 }

    @inlinable
    static var compressedx962PointByteCount: Int { 67 }

    @inlinable
    static var hashToFieldByteCount: Int { 98 }
}

struct OpenSSLGroupScalar<C: OpenSSLSupportedNISTCurve>: GroupScalar, CustomStringConvertible {
    var openSSLScalar: ArbitraryPrecisionInteger

    init(_ openSSLScalar: ArbitraryPrecisionInteger) {
        self.openSSLScalar = openSSLScalar
    }

    /// Deserializes a scalar from data.
    /// - Parameters:
    ///   - data: The serialized scalar
    ///   - reductionIsModOrder: Resulting number is taken "mod q" (characteristic) by default. Override by setting true if "mod p" (order) is desired.
    /// - Returns: The deserialized scalar
    init(bytes: Data, reductionIsModOrder: Bool = false) throws {
        if reductionIsModOrder {
            self.init(
                try ArbitraryPrecisionInteger(bytes: bytes).modulo(C.group.weierstrassCoefficients.field)
            )
        } else {
            self.init(try ArbitraryPrecisionInteger(bytes: bytes).modulo(C.group.order))
        }
    }

    static var random: Self {
        // Force-try: Protocol requires non-throwing and this can only throw if bounds are invalid.
        try! Self(.random(inclusiveMin: 0, exclusiveMax: C.group.order))
    }

    static func + (left: Self, right: Self) -> Self {
        // Force-try: Protocol requires non-throwing and this can only throw if modulus is invalid.
        try! Self(left.openSSLScalar.add(right.openSSLScalar, modulo: C.group.order))
    }

    static func - (left: Self, right: Self) -> Self {
        // Force-try: Protocol requires non-throwing and this can only throw if modulus is invalid.
        try! Self(left.openSSLScalar.sub(right.openSSLScalar, modulo: C.group.order))
    }

    static func ^ (left: Self, right: Int) -> Self {
        precondition(right == -1, "Unimplemented arbitrary exponentiation")
        // Force-try: Protocol requires non-throwing and this can only throw if modulus is invalid.
        return try! Self(left.openSSLScalar.inverse(modulo: C.group.order))
    }

    static func * (left: Self, right: Self) -> Self {
        // Force-try: Protocol requires non-throwing and this can only throw if modulus is invalid.
        try! Self(left.openSSLScalar.mul(right.openSSLScalar, modulo: C.group.order))
    }

    static prefix func - (left: Self) -> Self {
        // Force-try: Protocol requires non-throwing and this can only throw if modulus is invalid.
        try! Self(.zero.sub(left.openSSLScalar, modulo: C.group.order))
    }

    static func == (left: Self, right: Self) -> Bool {
        left.openSSLScalar == right.openSSLScalar
    }

    var rawRepresentation: Data {
        // Force-try: This can only throw if the requested size is not big enough to represent the point.
        try! Data(bytesOf: self.openSSLScalar, paddedToSize: C.orderByteCount)
    }

    var description: String {
        self.rawRepresentation.hexString
    }
}

struct OpenSSLCurvePoint<C: OpenSSLSupportedNISTCurve>: GroupElement {
    var ecPoint: EllipticCurvePoint
    typealias Scalar = OpenSSLGroupScalar<C>

    init(ecPoint: EllipticCurvePoint) {
        self.ecPoint = ecPoint
    }

    static var generator: Self {
        // Force-try: Protocol requires non-throwing and this can only throw if group has no generator.
        // TODO: `BoringSSLEllipticCurveGroup.generator` should probably be non-throwing, like `.order`.
        try! Self(ecPoint: C.group.generator)
    }

    static var random: Self {
        let randomBytes = SystemRandomNumberGenerator.randomBytes(count: C.group.order.byteCount)
        let dst = Data("Random EC Point Generation".utf8)
        // Force-try: Protocol requires non-throwing and this can only throw if called with the wrong group.
        let point = try! EllipticCurvePoint(hashing: randomBytes, to: C.group, domainSeparationTag: dst)
        return Self(ecPoint: point)
    }

    static func + (left: Self, right: Self) -> Self {
        // Force-try: Protocol requires non-throwing.
        try! Self(ecPoint: left.ecPoint.adding(right.ecPoint, on: C.group))
    }

    static func - (left: Self, right: Self) -> Self {
        // Force-try: Protocol requires non-throwing.
        try! Self(ecPoint: left.ecPoint.subtracting(right.ecPoint, on: C.group))
    }

    static prefix func - (left: Self) -> Self {
        // Force-try: Protocol requires non-throwing.
        try! Self(ecPoint: left.ecPoint.inverting(on: C.group))
    }

    static func * (left: Scalar, right: Self) -> Self {
        // Force-try: Protocol requires non-throwing.
        try! Self(ecPoint: .multiplying(right.ecPoint, by: left.openSSLScalar, on: C.group))
    }

    static func == (left: Self, right: Self) -> Bool {
        left.ecPoint.isEqual(to: right.ecPoint, on: C.group)
    }
}

extension OpenSSLCurvePoint {
    var compressedRepresentation: Data {
        try! self.ecPoint.x962Representation(compressed: true, on: C.group)
    }
}

extension OpenSSLCurvePoint: OPRFGroupElement {
    init(oprfRepresentation data: Data) throws {
        let point = try EllipticCurvePoint(x962Representation: data, on: C.group)
        self.init(ecPoint: point)
    }

    var oprfRepresentation: Data { self.compressedRepresentation }
}

struct OpenSSLGroup<C: OpenSSLSupportedNISTCurve>: Group {
    typealias Element = OpenSSLCurvePoint<C>

    static var cofactor: Int {
        // NOTE: Practically, this is always 1, because this type is only generic over our NIST curves.
        C.cofactor
    }
}

@available(macOS 10.15, iOS 13.2, tvOS 13.2, watchOS 6.1, *)
struct OpenSSLHashToCurve<C: OpenSSLSupportedNISTCurve>: HashToGroup {
    typealias H = C.H
    typealias GE = OpenSSLCurvePoint<C>
    typealias G = OpenSSLGroup<C>

    static func hashToScalar(_ data: Data, domainSeparationString: Data) throws -> GE.Scalar {
        // Force-unwrap: HashToField is guaranteed to produce one or more elements, so .first is always non-nil.
        try HashToField<C>.hashToField(
            data,
            outputElementCount: 1,
            dst: Data("HashToScalar-".utf8) + domainSeparationString,
            outputSize: C.hashToFieldByteCount,
            reductionIsModOrder: false
        ).first!
    }

    static func hashToGroup(_ data: Data, domainSeparationString: Data) -> GE {
        precondition(G.cofactor == 1, "H2C doesn't have support for clearing co-factors.")
        precondition(!domainSeparationString.isEmpty, "DST must be non-empty.")
        switch C.self {
        case is P256.Type:
            let point = try! EllipticCurvePoint(
                hashing: data,
                to: P256.group,
                domainSeparationTag: domainSeparationString
            )
            return OpenSSLCurvePoint(ecPoint: point)
        case is P384.Type:
            let point = try! EllipticCurvePoint(
                hashing: data,
                to: P384.group,
                domainSeparationTag: domainSeparationString
            )
            return OpenSSLCurvePoint(ecPoint: point)
        case is P521.Type:
            // BoringSSL doesn't have implementation of P521_XMD:SHA-512_SSWU_RO_.
            fatalError("HashToGroup not supported for type: \(C.self).")
        default:
            fatalError("HashToGroup not supported for type: \(C.self).")
        }
    }
}
