//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// NOTE: This file is unconditionally compiled because some helpers are used to create Security.fw keys from test vectors.
@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims
import Foundation
import Crypto

internal enum BIOHelper {
    static func withReadOnlyMemoryBIO<ReturnValue>(
        wrapping pointer: UnsafeRawBufferPointer, _ block: (UnsafeMutablePointer<BIO>) throws -> ReturnValue
    ) rethrows -> ReturnValue {
        let bio = CCryptoBoringSSL_BIO_new_mem_buf(pointer.baseAddress, pointer.count)!
        defer {
            CCryptoBoringSSL_BIO_free(bio)
        }

        return try block(bio)
    }

    static func withReadOnlyMemoryBIO<ReturnValue>(
        wrapping pointer: UnsafeBufferPointer<UInt8>, _ block: (UnsafeMutablePointer<BIO>) throws -> ReturnValue
    ) rethrows -> ReturnValue {
        let bio = CCryptoBoringSSL_BIO_new_mem_buf(pointer.baseAddress, pointer.count)!
        defer {
            CCryptoBoringSSL_BIO_free(bio)
        }

        return try block(bio)
    }

    static func withWritableMemoryBIO<ReturnValue>(_ block: (UnsafeMutablePointer<BIO>) throws -> ReturnValue) rethrows -> ReturnValue {
        let bio = CCryptoBoringSSL_BIO_new(CCryptoBoringSSL_BIO_s_mem())!
        defer {
            CCryptoBoringSSL_BIO_free(bio)
        }

        return try block(bio)
    }
}

extension Data {
    init(copyingMemoryBIO bio: UnsafeMutablePointer<BIO>) throws {
        var innerPointer: UnsafePointer<UInt8>? = nil
        var innerLength = 0

        guard 1 == CCryptoBoringSSL_BIO_mem_contents(bio, &innerPointer, &innerLength) else {
            throw CryptoKitError.internalBoringSSLError()
        }

        self = Data(UnsafeBufferPointer(start: innerPointer, count: innerLength))
    }
}

extension String {
    init(copyingUTF8MemoryBIO bio: UnsafeMutablePointer<BIO>) throws {
        var innerPointer: UnsafePointer<UInt8>? = nil
        var innerLength = 0

        guard 1 == CCryptoBoringSSL_BIO_mem_contents(bio, &innerPointer, &innerLength) else {
            throw CryptoKitError.internalBoringSSLError()
        }

        self = String(decoding: UnsafeBufferPointer(start: innerPointer, count: innerLength), as: UTF8.self)
    }
}

extension FixedWidthInteger {
    func withBignumPointer<ReturnType>(_ block: (UnsafeMutablePointer<BIGNUM>) throws -> ReturnType) rethrows -> ReturnType {
        precondition(self.bitWidth <= UInt.bitWidth)

        var bn = BIGNUM()
        CCryptoBoringSSL_BN_init(&bn)
        defer {
            CCryptoBoringSSL_BN_clear(&bn)
        }

        CCryptoBoringSSL_BN_set_word(&bn, .init(self))

        return try block(&bn)
    }
}

extension BIGNUM {
    /// Construct a BoringSSL `BIGNUM` from a hex string.
    ///
    /// - Parameter hexString: Hex byte string (big-endian, no `0x` prefix, may start with `-` for a negative number).
    init(hexString: String) throws {
        self = BIGNUM()
        try hexString.withCString { hexStringPtr in
            /// `BN_hex2bin` takes a `BIGNUM **` so we need a double WUMP dance.
            try withUnsafeMutablePointer(to: &self) { selfPtr in
                var selfPtr: UnsafeMutablePointer<BIGNUM>? = selfPtr
                try withUnsafeMutablePointer(to: &selfPtr) { selfPtrPtr in
                    /// `BN_hex2bin` returns the number of bytes of `in` processed or zero on error.
                    guard CCryptoBoringSSL_BN_hex2bn(selfPtrPtr, hexStringPtr) == hexString.count else {
                        throw CryptoKitError.incorrectParameterSize
                    }
                }
            }
        }
    }

    func sub(_ rhs: Self, modulo modulus: Self? = nil) -> Self {
        var result = BIGNUM()

        let rc = withUnsafeMutablePointer(to: &result) { resultPtr in
            withUnsafePointer(to: self) { selfPtr in
                withUnsafePointer(to: rhs) { rhsPtr in
                    if let modulus {
                        let bnCtx = CCryptoBoringSSL_BN_CTX_new()!
                        defer { CCryptoBoringSSL_BN_CTX_free(bnCtx) }
                        return withUnsafePointer(to: modulus) { modulusPtr in
                            CCryptoBoringSSL_BN_mod_sub(resultPtr, selfPtr, rhsPtr, modulusPtr, bnCtx)
                        }
                    } else {
                        return CCryptoBoringSSL_BN_sub(resultPtr, selfPtr, rhsPtr)
                    }
                }
            }
        }
        precondition(rc == 1, "Unable to allocate memory for new BIGNUM")

        return result
    }

    func modulo(_ mod: Self, nonNegative: Bool = false) -> Self {
        var result = BIGNUM()

        let rc = withUnsafeMutablePointer(to: &result) { resultPtr in
            withUnsafePointer(to: self) { selfPtr in
                withUnsafePointer(to: mod) { modPtr in
                    let bnCtx = CCryptoBoringSSL_BN_CTX_new()!
                    defer { CCryptoBoringSSL_BN_CTX_free(bnCtx) }
                    if nonNegative {
                        return CCryptoBoringSSL_BN_nnmod(resultPtr, selfPtr, modPtr, bnCtx)
                    } else {
                        return CCryptoBoringSSLShims_BN_mod(resultPtr, selfPtr, modPtr, bnCtx)
                    }
                }
            }
        }
        precondition(rc == 1, "Unable to allocate memory for new BIGNUM")

        return result
    }

    func inverse(modulo mod: Self) -> Self {
        var result = BIGNUM()

        let rc = withUnsafeMutablePointer(to: &result) { resultPtr in
            withUnsafePointer(to: self) { selfPtr in
                withUnsafePointer(to: mod) { modPtr in
                    let bnCtx = CCryptoBoringSSL_BN_CTX_new()!
                    defer { CCryptoBoringSSL_BN_CTX_free(bnCtx) }
                    return CCryptoBoringSSL_BN_mod_inverse(resultPtr, selfPtr, modPtr, bnCtx)
                }
            }
        }
        precondition(rc != nil, "Unable to allocate memory for new BIGNUM")

        return result
    }
}

extension _RSA.BlindSigning.PublicKey {
    /// Construct a platform-specific RSA public key with the specified parameters.
    ///
    /// This constructor is used in tests in cases where test vectors provide the key information this way.
    ///
    /// Only the BoringSSL backend provides APIs to create the key from its parameters so we first create a BoringSSL
    /// key, serialize it to PEM format, and then construct a platform specific key from the PEM representation.
    internal init(nHexString: String, eHexString: String) throws {
        var n = try BIGNUM(hexString: nHexString)
        defer { CCryptoBoringSSL_BN_clear_free(&n) }
        var e = try BIGNUM(hexString: eHexString)
        defer { CCryptoBoringSSL_BN_clear_free(&e) }

        // Create BoringSSL RSA key.
        let rsaPtr = CCryptoBoringSSL_RSA_new_public_key(&n, &e)
        defer { CCryptoBoringSSL_RSA_free(rsaPtr) }

        // Get PEM representation for key.
        let pemRepresentation = BIOHelper.withWritableMemoryBIO { bio in
            precondition(CCryptoBoringSSL_PEM_write_bio_RSAPublicKey(bio, rsaPtr) == 1)
            return try! String(copyingUTF8MemoryBIO: bio)
        }

        // Create a key (which might be backed by Security framework) from PEM representation.
        try self.init(pemRepresentation: pemRepresentation)
    }
}


extension _RSA.BlindSigning.PrivateKey {
    /// Construct a platform-specific RSA private key with the specified parameters.
    ///
    /// This constructor is used in tests in cases where test vectors provide the key information this way.
    ///
    /// Only the BoringSSL backend provides APIs to create the key from its parameters so we first create a BoringSSL
    /// key, serialize it to PEM format, and then construct a platform specific key from the PEM representation.
    internal init(nHexString: String, eHexString: String, dHexString: String, pHexString: String, qHexString: String) throws {
        var n = try BIGNUM(hexString: nHexString)
        defer { CCryptoBoringSSL_BN_clear_free(&n) }
        var e = try BIGNUM(hexString: eHexString)
        defer { CCryptoBoringSSL_BN_clear_free(&e) }
        var d = try BIGNUM(hexString: dHexString)
        defer { CCryptoBoringSSL_BN_clear_free(&d) }
        var p = try BIGNUM(hexString: pHexString)
        defer { CCryptoBoringSSL_BN_clear_free(&p) }
        var q = try BIGNUM(hexString: qHexString)
        defer { CCryptoBoringSSL_BN_clear_free(&q) }

        // Compute the CRT params.
        var one = try BIGNUM(hexString: "01")
        defer { CCryptoBoringSSL_BN_clear_free(&one) }
        var dp = d.modulo(p.sub(one))
        defer { CCryptoBoringSSL_BN_clear_free(&dp) }
        var dq = d.modulo(q.sub(one))
        defer { CCryptoBoringSSL_BN_clear_free(&dq) }
        var qi = q.inverse(modulo: p)
        defer { CCryptoBoringSSL_BN_clear_free(&qi) }

        // Create BoringSSL RSA key.
        let rsaPtr = CCryptoBoringSSL_RSA_new_private_key(&n, &e, &d, &p, &q, &dp, &dq, &qi)
        defer { CCryptoBoringSSL_RSA_free(rsaPtr) }

        // Get PEM representation for key.
        let pemRepresentation = BIOHelper.withWritableMemoryBIO { bio in
            precondition(CCryptoBoringSSL_PEM_write_bio_RSAPrivateKey(bio, rsaPtr, nil, nil, 0, nil, nil) == 1)
            return try! String(copyingUTF8MemoryBIO: bio)
        }

        // Create a key (which might be backed by Security framework) from PEM representation.
        try self.init(pemRepresentation: pemRepresentation)
    }
}
