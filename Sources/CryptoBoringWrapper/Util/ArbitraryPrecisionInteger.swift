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
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A wrapper around the OpenSSL BIGNUM object that is appropriately lifetime managed,
/// and that provides better Swift types for this object.
@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
package struct ArbitraryPrecisionInteger: @unchecked Sendable {
    private var _backing: BackingStorage

    @usableFromInline
    package init() {
        self._backing = BackingStorage()
    }

    package init(copying original: UnsafePointer<BIGNUM>) throws {
        self._backing = try BackingStorage(copying: original)
    }

    @usableFromInline
    package init(_ original: ArbitraryPrecisionInteger) throws {
        self._backing = try BackingStorage(copying: original._backing)
    }

    @usableFromInline
    package init(integerLiteral value: Int64) {
        self._backing = BackingStorage(value)
    }
}

// MARK: - BackingStorage

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArbitraryPrecisionInteger {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    fileprivate final class BackingStorage {
        private var _backing: BIGNUM

        init() {
            self._backing = BIGNUM()
            CCryptoBoringSSL_BN_init(&self._backing)
        }

        init(copying original: UnsafePointer<BIGNUM>) throws {
            self._backing = BIGNUM()
            guard CCryptoBoringSSL_BN_copy(&self._backing, original) != nil else {
                throw CryptoBoringWrapperError.internalBoringSSLError()
            }
        }

        init(copying original: BackingStorage) throws {
            self._backing = BIGNUM()

            try original.withUnsafeMutableBignumPointer { bnPtr in
                guard CCryptoBoringSSL_BN_copy(&self._backing, bnPtr) != nil else {
                    throw CryptoBoringWrapperError.internalBoringSSLError()
                }
            }
        }

        init(_ value: Int64) {
            self._backing = BIGNUM()
            let rc = CCryptoBoringSSL_BN_set_u64(&self._backing, value.magnitude)
            precondition(rc == 1, "Unable to allocate memory for new ArbitraryPrecisionInteger")

            if value < 0 {
                CCryptoBoringSSL_BN_set_negative(&self._backing, 1)
            }
        }

        deinit {
            CCryptoBoringSSL_BN_clear_free(&self._backing)
        }
    }
}

// MARK: - Extra initializers

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArbitraryPrecisionInteger {
    @usableFromInline
    package init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        self._backing = try BackingStorage(bytes: bytes)
    }

    /// Create an `ArbitraryPrecisionInteger` from a hex string.
    ///
    /// - Parameter hexString: Hex byte string (big-endian, no `0x` prefix, may start with `-` for a negative number).
    @usableFromInline
    package init(hexString: String) throws {
        self._backing = try BackingStorage(hexString: hexString)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArbitraryPrecisionInteger.BackingStorage {
    convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        self.init()

        let rc: UnsafeMutablePointer<BIGNUM>? = bytes.withUnsafeBytes { bytesPointer in
            CCryptoBoringSSLShims_BN_bin2bn(
                bytesPointer.baseAddress,
                bytesPointer.count,
                &self._backing
            )
        }
        guard rc != nil else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }
    }

    @inlinable
    convenience init(hexString: String) throws {
        self.init()
        try hexString.withCString { hexStringPtr in
            /// `BN_hex2bin` takes a `BIGNUM **` so we need a double WUMP dance.
            try withUnsafeMutablePointer(to: &self._backing) { backingPtr in
                var backingPtr: UnsafeMutablePointer<BIGNUM>? = backingPtr
                try withUnsafeMutablePointer(to: &backingPtr) { backingPtrPtr in
                    /// `BN_hex2bin` returns the number of bytes of `in` processed or zero on error.
                    guard CCryptoBoringSSL_BN_hex2bn(backingPtrPtr, hexStringPtr) == hexString.count else {
                        throw CryptoBoringWrapperError.incorrectParameterSize
                    }
                }
            }
        }
    }
}

// MARK: - Pointer helpers

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArbitraryPrecisionInteger {
    package func withUnsafeBignumPointer<T>(
        _ body: (UnsafePointer<BIGNUM>) throws -> T
    ) rethrows
        -> T
    {
        try self._backing.withUnsafeBignumPointer(body)
    }

    package mutating func withUnsafeMutableBignumPointer<T>(
        _ body: (UnsafeMutablePointer<BIGNUM>) throws -> T
    ) rethrows -> T {
        if !isKnownUniquelyReferenced(&self._backing) {
            // Failing to CoW is a fatal error here.
            self._backing = try! BackingStorage(copying: self._backing)
        }

        return try self._backing.withUnsafeMutableBignumPointer(body)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArbitraryPrecisionInteger.BackingStorage {
    func withUnsafeBignumPointer<T>(_ body: (UnsafePointer<BIGNUM>) throws -> T) rethrows -> T {
        try body(&self._backing)
    }

    func withUnsafeMutableBignumPointer<T>(
        _ body: (UnsafeMutablePointer<BIGNUM>) throws -> T
    )
        rethrows -> T
    {
        try body(&self._backing)
    }
}

// MARK: - Other helpers

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArbitraryPrecisionInteger {
    @usableFromInline static func _compare(
        lhs: ArbitraryPrecisionInteger,
        rhs: ArbitraryPrecisionInteger
    ) -> CInt {
        lhs.withUnsafeBignumPointer { lhsPtr in
            rhs.withUnsafeBignumPointer { rhsPtr in
                CCryptoBoringSSL_BN_cmp(lhsPtr, rhsPtr)
            }
        }
    }

    // This lets us check the sign of an ArbitraryPrecisionInteger.
    @usableFromInline var _positive: Bool {
        self.withUnsafeBignumPointer {
            CCryptoBoringSSL_BN_is_negative($0) == 0
        }
    }

    @usableFromInline
    package func squared() -> ArbitraryPrecisionInteger {
        var result = ArbitraryPrecisionInteger()
        let rc = result.withUnsafeMutableBignumPointer { resultPtr in
            self.withUnsafeBignumPointer { selfPtr in
                ArbitraryPrecisionInteger.withUnsafeBN_CTX { bnCtx in
                    CCryptoBoringSSL_BN_sqr(resultPtr, selfPtr, bnCtx)
                }
            }
        }
        precondition(rc == 1, "Unable to allocate memory for new ArbitraryPrecisionIntegers")
        return result
    }

    @usableFromInline
    package func positiveSquareRoot() throws -> ArbitraryPrecisionInteger {
        var result = ArbitraryPrecisionInteger()
        let rc = result.withUnsafeMutableBignumPointer { resultPtr in
            self.withUnsafeBignumPointer { selfPtr in
                ArbitraryPrecisionInteger.withUnsafeBN_CTX { bnCtx in
                    CCryptoBoringSSL_BN_sqrt(resultPtr, selfPtr, bnCtx)
                }
            }
        }

        guard rc == 1 else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }
        return result
    }

    @usableFromInline
    package var byteCount: Int {
        self._backing.withUnsafeBignumPointer {
            Int(CCryptoBoringSSL_BN_num_bytes($0))
        }
    }

    /// Some functions require a BN_CTX parameter: this obtains one with a scoped lifetime.
    private static func withUnsafeBN_CTX<T>(_ body: (OpaquePointer) throws -> T) rethrows -> T {
        // We force unwrap here because this call can only fail if the allocator is broken, and if
        // the allocator fails we don't have long to live anyway.
        let bnCtx = CCryptoBoringSSL_BN_CTX_new()!
        defer {
            CCryptoBoringSSL_BN_CTX_free(bnCtx)
        }

        return try body(bnCtx)
    }
}

// MARK: - Equatable

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArbitraryPrecisionInteger: Equatable {
    @inlinable
    package static func == (lhs: ArbitraryPrecisionInteger, rhs: ArbitraryPrecisionInteger) -> Bool {
        self._compare(lhs: lhs, rhs: rhs) == 0
    }
}

// MARK: - Comparable

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArbitraryPrecisionInteger: Comparable {
    @inlinable
    package static func < (lhs: ArbitraryPrecisionInteger, rhs: ArbitraryPrecisionInteger) -> Bool {
        self._compare(lhs: lhs, rhs: rhs) < 0
    }

    @inlinable
    package static func <= (lhs: ArbitraryPrecisionInteger, rhs: ArbitraryPrecisionInteger) -> Bool {
        self._compare(lhs: lhs, rhs: rhs) <= 0
    }

    @inlinable
    package static func > (lhs: ArbitraryPrecisionInteger, rhs: ArbitraryPrecisionInteger) -> Bool {
        self._compare(lhs: lhs, rhs: rhs) > 0
    }

    @inlinable
    package static func >= (lhs: ArbitraryPrecisionInteger, rhs: ArbitraryPrecisionInteger) -> Bool {
        self._compare(lhs: lhs, rhs: rhs) >= 0
    }
}

// MARK: - ExpressibleByIntegerLiteral

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArbitraryPrecisionInteger: ExpressibleByIntegerLiteral {}

// MARK: - AdditiveArithmetic

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArbitraryPrecisionInteger: AdditiveArithmetic {
    @inlinable
    package static var zero: ArbitraryPrecisionInteger {
        0
    }

    @usableFromInline
    package static func + (
        lhs: ArbitraryPrecisionInteger,
        rhs: ArbitraryPrecisionInteger
    )
        -> ArbitraryPrecisionInteger
    {
        var result = ArbitraryPrecisionInteger()

        let rc = result.withUnsafeMutableBignumPointer { resultPtr in
            lhs.withUnsafeBignumPointer { lhsPtr in
                rhs.withUnsafeBignumPointer { rhsPtr in
                    CCryptoBoringSSL_BN_add(resultPtr, lhsPtr, rhsPtr)
                }
            }
        }
        precondition(rc == 1, "Unable to allocate memory for new ArbitraryPrecisionInteger")

        return result
    }

    @usableFromInline
    package static func += (lhs: inout ArbitraryPrecisionInteger, rhs: ArbitraryPrecisionInteger) {
        let rc = lhs.withUnsafeMutableBignumPointer { lhsPtr in
            rhs.withUnsafeBignumPointer { rhsPtr in
                CCryptoBoringSSL_BN_add(lhsPtr, lhsPtr, rhsPtr)
            }
        }
        precondition(rc == 1, "Unable to allocate memory for new ArbitraryPrecisionInteger")
    }

    @usableFromInline
    package static func - (
        lhs: ArbitraryPrecisionInteger,
        rhs: ArbitraryPrecisionInteger
    )
        -> ArbitraryPrecisionInteger
    {
        var result = ArbitraryPrecisionInteger()

        let rc = result.withUnsafeMutableBignumPointer { resultPtr in
            lhs.withUnsafeBignumPointer { lhsPtr in
                rhs.withUnsafeBignumPointer { rhsPtr in
                    CCryptoBoringSSL_BN_sub(resultPtr, lhsPtr, rhsPtr)
                }
            }
        }
        precondition(rc == 1, "Unable to allocate memory for new ArbitraryPrecisionInteger")

        return result
    }

    @usableFromInline
    package static func -= (lhs: inout ArbitraryPrecisionInteger, rhs: ArbitraryPrecisionInteger) {
        let rc = lhs.withUnsafeMutableBignumPointer { lhsPtr in
            rhs.withUnsafeBignumPointer { rhsPtr in
                CCryptoBoringSSL_BN_sub(lhsPtr, lhsPtr, rhsPtr)
            }
        }
        precondition(rc == 1, "Unable to allocate memory for new ArbitraryPrecisionInteger")
    }
}

// MARK: - Numeric

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArbitraryPrecisionInteger: Numeric {
    @usableFromInline
    package typealias Magnitude = Self

    @usableFromInline
    package var magnitude: Magnitude {
        if self._positive {
            return self
        }

        // We are negative, we need a copy.
        var copy = self
        copy.withUnsafeMutableBignumPointer {
            // BN_set_negative is poorly named: it should be "BN_set_sign_bit", which we set to 0.
            CCryptoBoringSSL_BN_set_negative($0, 0)
        }
        return copy
    }

    @usableFromInline
    package static func * (
        lhs: ArbitraryPrecisionInteger,
        rhs: ArbitraryPrecisionInteger
    )
        -> ArbitraryPrecisionInteger
    {
        var result = ArbitraryPrecisionInteger()

        let rc = result.withUnsafeMutableBignumPointer { resultPtr in
            lhs.withUnsafeBignumPointer { lhsPtr in
                rhs.withUnsafeBignumPointer { rhsPtr in
                    ArbitraryPrecisionInteger.withUnsafeBN_CTX { bnCtx in
                        CCryptoBoringSSL_BN_mul(resultPtr, lhsPtr, rhsPtr, bnCtx)
                    }
                }
            }
        }
        precondition(rc == 1, "Unable to allocate memory for new ArbitraryPrecisionInteger")

        return result
    }

    @usableFromInline
    package static func *= (lhs: inout ArbitraryPrecisionInteger, rhs: ArbitraryPrecisionInteger) {
        let rc = lhs.withUnsafeMutableBignumPointer { lhsPtr in
            rhs.withUnsafeBignumPointer { rhsPtr in
                ArbitraryPrecisionInteger.withUnsafeBN_CTX { bnCtx in
                    CCryptoBoringSSL_BN_mul(lhsPtr, lhsPtr, rhsPtr, bnCtx)
                }
            }
        }
        precondition(rc == 1, "Unable to allocate memory for new ArbitraryPrecisionInteger")
    }

    @inlinable
    package init?<T: BinaryInteger>(exactly integer: T) {
        fatalError("Not currently implemented")
    }
}

// MARK: - Modular arithmetic

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArbitraryPrecisionInteger {
    @usableFromInline
    package func modulo(
        _ mod: ArbitraryPrecisionInteger,
        nonNegative: Bool = false
    ) throws
        -> ArbitraryPrecisionInteger
    {
        var result = ArbitraryPrecisionInteger()

        let rc = result.withUnsafeMutableBignumPointer { resultPtr in
            self.withUnsafeBignumPointer { selfPtr in
                mod.withUnsafeBignumPointer { modPtr in
                    ArbitraryPrecisionInteger.withUnsafeBN_CTX { bnCtx in
                        if nonNegative {
                            CCryptoBoringSSL_BN_nnmod(resultPtr, selfPtr, modPtr, bnCtx)
                        } else {
                            CCryptoBoringSSLShims_BN_mod(resultPtr, selfPtr, modPtr, bnCtx)
                        }
                    }
                }
            }
        }
        guard rc == 1 else { throw CryptoBoringWrapperError.internalBoringSSLError() }

        return result
    }

    @usableFromInline
    package func inverse(modulo mod: ArbitraryPrecisionInteger) throws -> ArbitraryPrecisionInteger {
        var result = ArbitraryPrecisionInteger()

        let rc = result.withUnsafeMutableBignumPointer { resultPtr in
            self.withUnsafeBignumPointer { selfPtr in
                mod.withUnsafeBignumPointer { modPtr in
                    ArbitraryPrecisionInteger.withUnsafeBN_CTX { bnCtx in
                        CCryptoBoringSSL_BN_mod_inverse(resultPtr, selfPtr, modPtr, bnCtx)
                    }
                }
            }
        }
        guard rc != nil else { throw CryptoBoringWrapperError.internalBoringSSLError() }

        return result
    }

    @usableFromInline
    package static func inverse(
        lhs: ArbitraryPrecisionInteger,
        modulo mod: ArbitraryPrecisionInteger
    ) throws -> ArbitraryPrecisionInteger {
        try ArbitraryPrecisionInteger(lhs).inverse(modulo: mod)
    }

    @usableFromInline
    package func add(
        _ rhs: ArbitraryPrecisionInteger,
        modulo modulus: ArbitraryPrecisionInteger? = nil
    ) throws -> ArbitraryPrecisionInteger {
        guard let modulus else { return self + rhs }
        var result = ArbitraryPrecisionInteger()

        let rc = result.withUnsafeMutableBignumPointer { resultPtr in
            self.withUnsafeBignumPointer { selfPtr in
                rhs.withUnsafeBignumPointer { rhsPtr in
                    modulus.withUnsafeBignumPointer { modulusPtr in
                        ArbitraryPrecisionInteger.withUnsafeBN_CTX { bnCtx in
                            CCryptoBoringSSL_BN_mod_add(resultPtr, selfPtr, rhsPtr, modulusPtr, bnCtx)
                        }
                    }
                }
            }
        }
        guard rc == 1 else { throw CryptoBoringWrapperError.internalBoringSSLError() }

        return result
    }

    @usableFromInline
    package func sub(
        _ rhs: ArbitraryPrecisionInteger,
        modulo modulus: ArbitraryPrecisionInteger? = nil
    ) throws -> ArbitraryPrecisionInteger {
        guard let modulus else { return self - rhs }
        var result = ArbitraryPrecisionInteger()

        let rc = result.withUnsafeMutableBignumPointer { resultPtr in
            self.withUnsafeBignumPointer { selfPtr in
                rhs.withUnsafeBignumPointer { rhsPtr in
                    modulus.withUnsafeBignumPointer { modulusPtr in
                        ArbitraryPrecisionInteger.withUnsafeBN_CTX { bnCtx in
                            CCryptoBoringSSL_BN_mod_sub(resultPtr, selfPtr, rhsPtr, modulusPtr, bnCtx)
                        }
                    }
                }
            }
        }
        guard rc == 1 else { throw CryptoBoringWrapperError.internalBoringSSLError() }

        return result
    }

    @usableFromInline
    package func mul(
        _ rhs: ArbitraryPrecisionInteger,
        modulo modulus: ArbitraryPrecisionInteger? = nil
    ) throws -> ArbitraryPrecisionInteger {
        guard let modulus else { return self * rhs }
        var result = ArbitraryPrecisionInteger()

        let rc = result.withUnsafeMutableBignumPointer { resultPtr in
            self.withUnsafeBignumPointer { selfPtr in
                rhs.withUnsafeBignumPointer { rhsPtr in
                    modulus.withUnsafeBignumPointer { modulusPtr in
                        ArbitraryPrecisionInteger.withUnsafeBN_CTX { bnCtx in
                            CCryptoBoringSSL_BN_mod_mul(resultPtr, selfPtr, rhsPtr, modulusPtr, bnCtx)
                        }
                    }
                }
            }
        }
        guard rc == 1 else { throw CryptoBoringWrapperError.internalBoringSSLError() }

        return result
    }
}

// MARK: - SignedNumeric

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArbitraryPrecisionInteger: SignedNumeric {
    @usableFromInline
    package mutating func negate() {
        let signBit: CInt = self._positive ? 1 : 0

        self.withUnsafeMutableBignumPointer {
            CCryptoBoringSSL_BN_set_negative($0, signBit)
        }
    }
}

// MARK: - Other arithmetic operations

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArbitraryPrecisionInteger {
    @usableFromInline
    package var trailingZeroBitCount: Int32 {
        self.withUnsafeBignumPointer {
            CCryptoBoringSSL_BN_count_low_zero_bits($0)
        }
    }

    @usableFromInline
    package static func gcd(
        _ a: ArbitraryPrecisionInteger,
        _ b: ArbitraryPrecisionInteger
    ) throws
        -> ArbitraryPrecisionInteger
    {
        var result = ArbitraryPrecisionInteger()

        guard
            result.withUnsafeMutableBignumPointer({ resultPtr in
                a.withUnsafeBignumPointer { aPtr in
                    b.withUnsafeBignumPointer { bPtr in
                        ArbitraryPrecisionInteger.withUnsafeBN_CTX { bnCtx in
                            CCryptoBoringSSL_BN_gcd(resultPtr, aPtr, bPtr, bnCtx)
                        }
                    }
                }
            }) == 1
        else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }

        return result
    }

    @usableFromInline
    package func isCoprime(with other: ArbitraryPrecisionInteger) throws -> Bool {
        try Self.gcd(self, other) == 1
    }

    @usableFromInline
    package static func random(
        inclusiveMin: UInt,
        exclusiveMax: ArbitraryPrecisionInteger
    ) throws
        -> ArbitraryPrecisionInteger
    {
        var result = ArbitraryPrecisionInteger()

        guard
            result.withUnsafeMutableBignumPointer({ resultPtr in
                exclusiveMax.withUnsafeBignumPointer { exclusiveMaxPtr in
                    CCryptoBoringSSL_BN_rand_range_ex(resultPtr, BN_ULONG(inclusiveMin), exclusiveMaxPtr)
                }
            }) == 1
        else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }

        return result
    }

    @usableFromInline
    package static func >> (lhs: ArbitraryPrecisionInteger, rhs: Int32) -> ArbitraryPrecisionInteger {
        var result = ArbitraryPrecisionInteger()

        let rc = result.withUnsafeMutableBignumPointer { resultPtr in
            lhs.withUnsafeBignumPointer { lhsPtr in
                CCryptoBoringSSL_BN_rshift(resultPtr, lhsPtr, rhs)
            }
        }

        precondition(rc == 1, "Unable to allocate memory for new ArbitraryPrecisionInteger")

        return result
    }

    @usableFromInline
    package static func / (
        lhs: ArbitraryPrecisionInteger,
        rhs: ArbitraryPrecisionInteger
    )
        -> ArbitraryPrecisionInteger
    {
        var result = ArbitraryPrecisionInteger()

        let rc = result.withUnsafeMutableBignumPointer { resultPtr in
            lhs.withUnsafeBignumPointer { lhsPtr in
                rhs.withUnsafeBignumPointer { rhsPtr in
                    ArbitraryPrecisionInteger.withUnsafeBN_CTX { bnCtx in
                        CCryptoBoringSSL_BN_div(resultPtr, nil, lhsPtr, rhsPtr, bnCtx)
                    }
                }
            }
        }
        precondition(rc == 1, "Unable to allocate memory for new ArbitraryPrecisionInteger")

        return result
    }

    @usableFromInline
    package var isEven: Bool {
        self.withUnsafeBignumPointer {
            CCryptoBoringSSL_BN_is_odd($0) == 0
        }
    }
}

// MARK: - Serializing

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Data {
    /// Serializes an ArbitraryPrecisionInteger padded out to a certain minimum size.
    @usableFromInline
    package mutating func append(
        bytesOf integer: ArbitraryPrecisionInteger,
        paddedToSize paddingSize: Int
    ) throws {
        let byteCount = integer.byteCount

        guard paddingSize >= byteCount else {
            throw CryptoBoringWrapperError.incorrectParameterSize
        }

        // To extend the data we need to write some zeroes into it.
        self.append(contentsOf: repeatElement(0, count: paddingSize))

        let written: Int = self.withUnsafeMutableBytes { bytesPtr in
            // We want to write to the _end_ of the memory we just allocated, as we want to pad with leading zeroes.
            let bytesPtr = UnsafeMutableRawBufferPointer(rebasing: bytesPtr.suffix(byteCount))
            assert(bytesPtr.count == byteCount)

            return integer.withUnsafeBignumPointer { bnPtr in
                CCryptoBoringSSLShims_BN_bn2bin(bnPtr, bytesPtr.baseAddress!)
            }
        }

        assert(written == byteCount)
    }

    @usableFromInline
    package init(bytesOf integer: ArbitraryPrecisionInteger, paddedToSize paddingSize: Int) throws {
        self.init(capacity: paddingSize)
        try self.append(bytesOf: integer, paddedToSize: paddingSize)
    }
}

// MARK: - Printing

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArbitraryPrecisionInteger: CustomDebugStringConvertible {
    @usableFromInline
    package var debugDescription: String {
        guard let bio = CCryptoBoringSSL_BIO_new(CCryptoBoringSSL_BIO_s_mem()) else {
            return "ArbitraryPrecisionInteger: (error generating representation)"
        }
        defer {
            CCryptoBoringSSL_BIO_free(bio)
        }

        let rc = self.withUnsafeBignumPointer {
            CCryptoBoringSSL_BN_print(bio, $0)
        }
        guard rc == 1 else {
            return "ArbitraryPrecisionInteger: (error generating representation)"
        }

        var stringPointer: UnsafePointer<UInt8>?
        var length: Int = 0

        guard CCryptoBoringSSL_BIO_mem_contents(bio, &stringPointer, &length) == 1 else {
            return "ArbitraryPrecisionInteger: (error generating representation)"
        }

        // This line looks scary but it's actually pretty safe.
        //
        // String.init(decoding:as:) treats the first argument as a Collection of UInt8, and so does not require it to be
        // null-terminated. It also doesn't take ownership of the data, instead copying the bytes in to its backing storage.
        //
        // The other note is that we don't need to free the pointer vended to us by BIO_mem_contents, as this is in fact an
        // interior pointer to the storage owned by the BIO. That pointer will therefore be freed when our deferred BIO_free
        // call above actually executes, which will be only after this String has been constructed.
        //
        // I know it looks gross, but it's basically right.
        return String(
            decoding: UnsafeBufferPointer(start: stringPointer, count: length),
            as: Unicode.UTF8.self
        )
    }
}
#endif  // CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
