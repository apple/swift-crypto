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
import Foundation

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
@usableFromInline
class FiniteFieldArithmeticContext {
    private var fieldSize: ArbitraryPrecisionInteger
    private var bnCtx: OpaquePointer

    @usableFromInline
    init(fieldSize: ArbitraryPrecisionInteger) throws {
        self.fieldSize = fieldSize
        guard let bnCtx = CCryptoBoringSSL_BN_CTX_new() else {
            throw CryptoKitError.internalBoringSSLError()
        }
        CCryptoBoringSSL_BN_CTX_start(bnCtx)
        self.bnCtx = bnCtx
    }

    deinit {
        CCryptoBoringSSL_BN_CTX_end(self.bnCtx)
        CCryptoBoringSSL_BN_CTX_free(self.bnCtx)
    }
}

// MARK: - Arithmetic operations

extension FiniteFieldArithmeticContext {
    @usableFromInline
    func square(_ input: ArbitraryPrecisionInteger) throws -> ArbitraryPrecisionInteger {
        var output = ArbitraryPrecisionInteger()

        let rc = input.withUnsafeBignumPointer { inputPointer in
            self.fieldSize.withUnsafeBignumPointer { fieldSizePointer in
                output.withUnsafeMutableBignumPointer { outputPointer in
                    CCryptoBoringSSL_BN_mod_sqr(outputPointer, inputPointer, fieldSizePointer, self.bnCtx)
                }
            }
        }

        guard rc == 1 else {
            throw CryptoKitError.internalBoringSSLError()
        }

        return output
    }

    @usableFromInline
    func multiply(_ x: ArbitraryPrecisionInteger, _ y: ArbitraryPrecisionInteger) throws -> ArbitraryPrecisionInteger {
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
            throw CryptoKitError.internalBoringSSLError()
        }

        return output
    }

    @usableFromInline
    func add(_ x: ArbitraryPrecisionInteger, _ y: ArbitraryPrecisionInteger) throws -> ArbitraryPrecisionInteger {
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
            throw CryptoKitError.internalBoringSSLError()
        }

        return output
    }

    @usableFromInline
    func subtract(_ x: ArbitraryPrecisionInteger, from y: ArbitraryPrecisionInteger) throws -> ArbitraryPrecisionInteger {
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
            throw CryptoKitError.internalBoringSSLError()
        }

        return output
    }

    @usableFromInline
    func positiveSquareRoot(_ x: ArbitraryPrecisionInteger) throws -> ArbitraryPrecisionInteger {
        let outputPointer = x.withUnsafeBignumPointer { xPointer in
            self.fieldSize.withUnsafeBignumPointer { fieldSizePointer in
                // We can't pass a pointer in as BN_mod_sqrt may attempt to free it.
                CCryptoBoringSSL_BN_mod_sqrt(nil, xPointer, fieldSizePointer, self.bnCtx)
            }
        }

        guard let actualOutputPointer = outputPointer else {
            throw CryptoKitError.internalBoringSSLError()
        }

        // Ok, we own this pointer now.
        defer {
            CCryptoBoringSSL_BN_free(outputPointer)
        }

        return try ArbitraryPrecisionInteger(copying: actualOutputPointer)
    }
}
