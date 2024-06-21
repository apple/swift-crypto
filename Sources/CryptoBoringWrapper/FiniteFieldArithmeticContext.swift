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
import CCryptoBoringSSL

/// A context for performing mathematical operations on ArbitraryPrecisionIntegers over a finite field.
///
/// A common part of elliptic curve mathematics is to perform arithmetic operations over a finite field. These require
/// performing modular arithmetic, and cannot be processed in the same way as regular math on these integers.
///
/// Most operations we perform over finite fields are part of repeated, larger arithmetic operations, so this object also
/// manages the lifetime of a `BN_CTX`. While `BN_CTX` is a silly data type, it does still have the effect of caching existing
/// `BIGNUM`s, so it's not a terrible idea to use it here.
///
/// Annoyingly, because of the way we have implemented ArbitraryPrecisionInteger, we can't actually use these temporary bignums
/// ourselves.
public final class FiniteFieldArithmeticContext {
    /* private but @usableFromInline */ @usableFromInline var fieldSize: ArbitraryPrecisionInteger
    /* private but @usableFromInline */ @usableFromInline var bnCtx: OpaquePointer

    @inlinable
    public init(fieldSize: ArbitraryPrecisionInteger) throws {
        self.fieldSize = fieldSize
        guard let bnCtx = CCryptoBoringSSL_BN_CTX_new() else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }
        CCryptoBoringSSL_BN_CTX_start(bnCtx)
        self.bnCtx = bnCtx
    }

    @inlinable
    deinit {
        CCryptoBoringSSL_BN_CTX_end(self.bnCtx)
        CCryptoBoringSSL_BN_CTX_free(self.bnCtx)
    }
}

// MARK: - Arithmetic operations

extension FiniteFieldArithmeticContext {
    @inlinable
    public func residue(_ x: ArbitraryPrecisionInteger) throws -> ArbitraryPrecisionInteger {
        var result = ArbitraryPrecisionInteger()

        guard (x.withUnsafeBignumPointer { xPtr in
            self.fieldSize.withUnsafeBignumPointer { modPtr in
                result.withUnsafeMutableBignumPointer { resultPtr in
                    CCryptoBoringSSL_BN_nnmod(resultPtr, xPtr, modPtr, self.bnCtx)
                }
            }
        }) == 1 else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }

        return result

    }

    @inlinable
    public func square(_ input: ArbitraryPrecisionInteger) throws -> ArbitraryPrecisionInteger {
        var output = ArbitraryPrecisionInteger()

        let rc = input.withUnsafeBignumPointer { inputPointer in
            self.fieldSize.withUnsafeBignumPointer { fieldSizePointer in
                output.withUnsafeMutableBignumPointer { outputPointer in
                    CCryptoBoringSSL_BN_mod_sqr(outputPointer, inputPointer, fieldSizePointer, self.bnCtx)
                }
            }
        }

        guard rc == 1 else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }

        return output
    }

    @inlinable
    public func multiply(_ x: ArbitraryPrecisionInteger, _ y: ArbitraryPrecisionInteger) throws -> ArbitraryPrecisionInteger {
        var output = ArbitraryPrecisionInteger()

        let rc = x.withUnsafeBignumPointer { xPointer in
            y.withUnsafeBignumPointer { yPointer in
                self.fieldSize.withUnsafeBignumPointer { fieldSizePointer in
                    output.withUnsafeMutableBignumPointer { outputPointer in
                        CCryptoBoringSSL_BN_mod_mul(outputPointer, xPointer, yPointer, fieldSizePointer, self.bnCtx)
                    }
                }
            }
        }

        guard rc == 1 else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }

        return output
    }

    @inlinable
    public func add(_ x: ArbitraryPrecisionInteger, _ y: ArbitraryPrecisionInteger) throws -> ArbitraryPrecisionInteger {
        var output = ArbitraryPrecisionInteger()

        let rc = x.withUnsafeBignumPointer { xPointer in
            y.withUnsafeBignumPointer { yPointer in
                self.fieldSize.withUnsafeBignumPointer { fieldSizePointer in
                    output.withUnsafeMutableBignumPointer { outputPointer in
                        CCryptoBoringSSL_BN_mod_add(outputPointer, xPointer, yPointer, fieldSizePointer, self.bnCtx)
                    }
                }
            }
        }

        guard rc == 1 else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }

        return output
    }

    @inlinable
    public func subtract(_ x: ArbitraryPrecisionInteger, from y: ArbitraryPrecisionInteger) throws -> ArbitraryPrecisionInteger {
        var output = ArbitraryPrecisionInteger()

        let rc = x.withUnsafeBignumPointer { xPointer in
            y.withUnsafeBignumPointer { yPointer in
                self.fieldSize.withUnsafeBignumPointer { fieldSizePointer in
                    output.withUnsafeMutableBignumPointer { outputPointer in
                        // Note the order of y and x.
                        CCryptoBoringSSL_BN_mod_sub(outputPointer, yPointer, xPointer, fieldSizePointer, self.bnCtx)
                    }
                }
            }
        }

        guard rc == 1 else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }

        return output
    }

    @inlinable
    public func positiveSquareRoot(_ x: ArbitraryPrecisionInteger) throws -> ArbitraryPrecisionInteger {
        let outputPointer = x.withUnsafeBignumPointer { xPointer in
            self.fieldSize.withUnsafeBignumPointer { fieldSizePointer in
                // We can't pass a pointer in as BN_mod_sqrt may attempt to free it.
                CCryptoBoringSSL_BN_mod_sqrt(nil, xPointer, fieldSizePointer, self.bnCtx)
            }
        }

        guard let actualOutputPointer = outputPointer else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }

        // Ok, we own this pointer now.
        defer {
            CCryptoBoringSSL_BN_free(outputPointer)
        }

        return try ArbitraryPrecisionInteger(copying: actualOutputPointer)
    }

    @inlinable
    public func inverse(_ x: ArbitraryPrecisionInteger) throws -> ArbitraryPrecisionInteger? {
        var result = ArbitraryPrecisionInteger()

        guard (result.withUnsafeMutableBignumPointer { resultPtr in
            x.withUnsafeBignumPointer { xPtr in
                self.fieldSize.withUnsafeBignumPointer { modPtr in
                    CCryptoBoringSSL_BN_mod_inverse(resultPtr, xPtr , modPtr, self.bnCtx)
                }
            }
        }) != nil else { return nil }

        return result
    }

    @inlinable
    public func pow(_ x: ArbitraryPrecisionInteger, _ p: ArbitraryPrecisionInteger) throws -> ArbitraryPrecisionInteger {
        try self.pow(x, p) { r, x, p, m, ctx, _ in CCryptoBoringSSL_BN_mod_exp(r, x, p, m, ctx) }
    }

    @inlinable
    public func pow(secret x: ArbitraryPrecisionInteger, _ p: ArbitraryPrecisionInteger) throws -> ArbitraryPrecisionInteger {
        guard x < self.fieldSize else { throw CryptoBoringWrapperError.incorrectParameterSize }
        return try self.pow(x, p, using: CCryptoBoringSSL_BN_mod_exp_mont)
    }

    @inlinable
    public func pow(secret x: ArbitraryPrecisionInteger, secret p: ArbitraryPrecisionInteger) throws -> ArbitraryPrecisionInteger {
        guard x < self.fieldSize else { throw CryptoBoringWrapperError.incorrectParameterSize }
        return try self.pow(x, p, using: CCryptoBoringSSL_BN_mod_exp_mont_consttime)
    }

    /* private but @usableFromInline */ @usableFromInline func pow(
        _ a: ArbitraryPrecisionInteger,
        _ b: ArbitraryPrecisionInteger,
        using method: (
            _ rr: UnsafeMutablePointer<BIGNUM>?,
            _ a: UnsafePointer<BIGNUM>?,
            _ p: UnsafePointer<BIGNUM>?,
            _ m: UnsafePointer<BIGNUM>?,
            _ ctx: OpaquePointer?,
            _ mont: UnsafePointer<BN_MONT_CTX>?
        ) -> Int32
    ) throws -> ArbitraryPrecisionInteger {
        var result = ArbitraryPrecisionInteger()

        guard result.withUnsafeMutableBignumPointer({ resultPtr in
            a.withUnsafeBignumPointer { aPtr in
                b.withUnsafeBignumPointer { bPtr in
                    self.fieldSize.withUnsafeBignumPointer { modPtr in
                        self.withUnsafeBN_MONT_CTX { montCtxPtr in
                            method(resultPtr, aPtr, bPtr, modPtr, self.bnCtx, montCtxPtr)
                        }
                    }
                }
            }
        }) == 1 else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }

        return result
    }

    /// Some functions require a `BN_MONT_CTX` parameter: this obtains one for the field modulus with a scoped lifetime.
    /* private but @usableFromInline */ @usableFromInline func withUnsafeBN_MONT_CTX<T>(_ body: (UnsafePointer<BN_MONT_CTX>) throws -> T) rethrows -> T {
        try self.fieldSize.withUnsafeBignumPointer { modPtr in
            // We force unwrap here because this call can only fail if the allocator is broken, and if
            // the allocator fails we don't have long to live anyway.
            let montCtx = CCryptoBoringSSL_BN_MONT_CTX_new_for_modulus(modPtr, self.bnCtx)!
            defer { CCryptoBoringSSL_BN_MONT_CTX_free(montCtx) }
            return try body(montCtx)
        }
    }
}
