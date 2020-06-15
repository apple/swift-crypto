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
@_implementationOnly import CCryptoBoringSSLShims
import Foundation

/// A wrapper around the OpenSSL BIGNUM object that is appropriately lifetime managed,
/// and that provides better Swift types for this object.
@usableFromInline
struct ArbitraryPrecisionInteger {
    private var _backing: BackingStorage

    @usableFromInline
    init() {
        self._backing = BackingStorage()
    }

    init(copying original: UnsafePointer<BIGNUM>) throws {
        self._backing = try BackingStorage(copying: original)
    }

    @usableFromInline
    init(_ original: ArbitraryPrecisionInteger) throws {
        self._backing = try BackingStorage(copying: original._backing)
    }

    @usableFromInline
    init(integerLiteral value: Int64) {
        self._backing = BackingStorage(value)
    }
}

// MARK: - BackingStorage

extension ArbitraryPrecisionInteger {
    final class BackingStorage {
        private var _backing: BIGNUM

        init() {
            self._backing = BIGNUM()
            CCryptoBoringSSL_BN_init(&self._backing)
        }

        init(copying original: UnsafePointer<BIGNUM>) throws {
            self._backing = BIGNUM()
            guard CCryptoBoringSSL_BN_copy(&self._backing, original) != nil else {
                throw CryptoKitError.internalBoringSSLError()
            }
        }

        init(copying original: BackingStorage) throws {
            self._backing = BIGNUM()

            try original.withUnsafeMutableBignumPointer { bnPtr in
                guard CCryptoBoringSSL_BN_copy(&self._backing, bnPtr) != nil else {
                    throw CryptoKitError.internalBoringSSLError()
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

extension ArbitraryPrecisionInteger {
    init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        self._backing = try BackingStorage(bytes: bytes)
    }
}

extension ArbitraryPrecisionInteger.BackingStorage {
    convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        self.init()

        let rc: UnsafeMutablePointer<BIGNUM>? = bytes.withUnsafeBytes { bytesPointer in
            CCryptoBoringSSLShims_BN_bin2bn(bytesPointer.baseAddress, bytesPointer.count, &self._backing)
        }
        guard rc != nil else {
            throw CryptoKitError.internalBoringSSLError()
        }
    }
}

// MARK: - Pointer helpers

extension ArbitraryPrecisionInteger {
    func withUnsafeBignumPointer<T>(_ body: (UnsafePointer<BIGNUM>) throws -> T) rethrows -> T {
        return try self._backing.withUnsafeBignumPointer(body)
    }

    mutating func withUnsafeMutableBignumPointer<T>(_ body: (UnsafeMutablePointer<BIGNUM>) throws -> T) rethrows -> T {
        if !isKnownUniquelyReferenced(&self._backing) {
            // Failing to CoW is a fatal error here.
            self._backing = try! BackingStorage(copying: self._backing)
        }

        return try self._backing.withUnsafeMutableBignumPointer(body)
    }
}

extension ArbitraryPrecisionInteger.BackingStorage {
    func withUnsafeBignumPointer<T>(_ body: (UnsafePointer<BIGNUM>) throws -> T) rethrows -> T {
        return try body(&self._backing)
    }

    func withUnsafeMutableBignumPointer<T>(_ body: (UnsafeMutablePointer<BIGNUM>) throws -> T) rethrows -> T {
        return try body(&self._backing)
    }
}

// MARK: - Other helpers

extension ArbitraryPrecisionInteger {
    /* private but @usableFromInline */ @usableFromInline static func _compare(lhs: ArbitraryPrecisionInteger, rhs: ArbitraryPrecisionInteger) -> CInt {
        return lhs.withUnsafeBignumPointer { lhsPtr in
            rhs.withUnsafeBignumPointer { rhsPtr in
                CCryptoBoringSSL_BN_cmp(lhsPtr, rhsPtr)
            }
        }
    }

    // This lets us check the sign of an ArbitraryPrecisionInteger.
    /* private but @usableFromInline */ @usableFromInline var _positive: Bool {
        return self.withUnsafeBignumPointer {
            CCryptoBoringSSL_BN_is_negative($0) == 0
        }
    }

    @usableFromInline
    func squared() -> ArbitraryPrecisionInteger {
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
    func positiveSquareRoot() throws -> ArbitraryPrecisionInteger {
        var result = ArbitraryPrecisionInteger()
        let rc = result.withUnsafeMutableBignumPointer { resultPtr in
            self.withUnsafeBignumPointer { selfPtr in
                ArbitraryPrecisionInteger.withUnsafeBN_CTX { bnCtx in
                    CCryptoBoringSSL_BN_sqrt(resultPtr, selfPtr, bnCtx)
                }
            }
        }

        guard rc == 1 else {
            throw CryptoKitError.internalBoringSSLError()
        }
        return result
    }

    @usableFromInline
    var byteCount: Int {
        return self._backing.withUnsafeBignumPointer {
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

extension ArbitraryPrecisionInteger: Equatable {
    @inlinable
    static func == (lhs: ArbitraryPrecisionInteger, rhs: ArbitraryPrecisionInteger) -> Bool {
        return self._compare(lhs: lhs, rhs: rhs) == 0
    }
}

// MARK: - Comparable

extension ArbitraryPrecisionInteger: Comparable {
    @inlinable
    static func < (lhs: ArbitraryPrecisionInteger, rhs: ArbitraryPrecisionInteger) -> Bool {
        return self._compare(lhs: lhs, rhs: rhs) < 0
    }

    @inlinable
    static func <= (lhs: ArbitraryPrecisionInteger, rhs: ArbitraryPrecisionInteger) -> Bool {
        return self._compare(lhs: lhs, rhs: rhs) <= 0
    }

    @inlinable
    static func > (lhs: ArbitraryPrecisionInteger, rhs: ArbitraryPrecisionInteger) -> Bool {
        return self._compare(lhs: lhs, rhs: rhs) > 0
    }

    @inlinable
    static func >= (lhs: ArbitraryPrecisionInteger, rhs: ArbitraryPrecisionInteger) -> Bool {
        return self._compare(lhs: lhs, rhs: rhs) >= 0
    }
}

// MARK: - ExpressibleByIntegerLiteral

extension ArbitraryPrecisionInteger: ExpressibleByIntegerLiteral {}

// MARK: - AdditiveArithmetic

extension ArbitraryPrecisionInteger: AdditiveArithmetic {
    @inlinable
    static var zero: ArbitraryPrecisionInteger {
        return 0
    }

    @usableFromInline
    static func + (lhs: ArbitraryPrecisionInteger, rhs: ArbitraryPrecisionInteger) -> ArbitraryPrecisionInteger {
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
    static func += (lhs: inout ArbitraryPrecisionInteger, rhs: ArbitraryPrecisionInteger) {
        let rc = lhs.withUnsafeMutableBignumPointer { lhsPtr in
            rhs.withUnsafeBignumPointer { rhsPtr in
                CCryptoBoringSSL_BN_add(lhsPtr, lhsPtr, rhsPtr)
            }
        }
        precondition(rc == 1, "Unable to allocate memory for new ArbitraryPrecisionInteger")
    }

    @usableFromInline
    static func - (lhs: ArbitraryPrecisionInteger, rhs: ArbitraryPrecisionInteger) -> ArbitraryPrecisionInteger {
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
    static func -= (lhs: inout ArbitraryPrecisionInteger, rhs: ArbitraryPrecisionInteger) {
        let rc = lhs.withUnsafeMutableBignumPointer { lhsPtr in
            rhs.withUnsafeBignumPointer { rhsPtr in
                CCryptoBoringSSL_BN_sub(lhsPtr, lhsPtr, rhsPtr)
            }
        }
        precondition(rc == 1, "Unable to allocate memory for new ArbitraryPrecisionInteger")
    }
}

// MARK: - Numeric

extension ArbitraryPrecisionInteger: Numeric {
    @usableFromInline
    typealias Magnitude = Self

    @usableFromInline
    var magnitude: Magnitude {
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
    static func * (lhs: ArbitraryPrecisionInteger, rhs: ArbitraryPrecisionInteger) -> ArbitraryPrecisionInteger {
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
    static func *= (lhs: inout ArbitraryPrecisionInteger, rhs: ArbitraryPrecisionInteger) {
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
    init?<T: BinaryInteger>(exactly integer: T) {
        fatalError("Not currently implemented")
    }
}

// MARK: - SignedNumeric

extension ArbitraryPrecisionInteger: SignedNumeric {
    @usableFromInline
    mutating func negate() {
        let signBit: CInt = self._positive ? 1 : 0

        self.withUnsafeMutableBignumPointer {
            CCryptoBoringSSL_BN_set_negative($0, signBit)
        }
    }
}

// MARK: - Serializing

extension Data {
    /// Serializes an ArbitraryPrecisionInteger padded out to a certain minimum size.
    @usableFromInline
    mutating func append(bytesOf integer: ArbitraryPrecisionInteger, paddedToSize paddingSize: Int) throws {
        let byteCount = integer.byteCount

        guard paddingSize >= byteCount else {
            throw CryptoKitError.incorrectParameterSize
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
}

// MARK: - Printing

extension ArbitraryPrecisionInteger: CustomDebugStringConvertible {
    @usableFromInline
    var debugDescription: String {
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
        return String(decoding: UnsafeBufferPointer(start: stringPointer, count: length), as: Unicode.UTF8.self)
    }
}
