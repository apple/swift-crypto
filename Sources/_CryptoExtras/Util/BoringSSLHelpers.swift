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

// NOTE: This file is unconditionally compiled because RSABSSA is implemented using BoringSSL on all platforms.
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

extension _RSA.BlindSigning.PublicKey {
    /// Construct a platform-specific RSA public key with the specified parameters.
    ///
    /// This constructor is used in tests in cases where test vectors provide the key information this way.
    ///
    /// Only the BoringSSL backend provides APIs to create the key from its parameters so we first create a BoringSSL
    /// key, serialize it to PEM format, and then construct a platform specific key from the PEM representation.
    internal init(nHexString: String, eHexString: String, parameters: Parameters) throws {
        let n = try ArbitraryPrecisionInteger(hexString: nHexString)
        let e = try ArbitraryPrecisionInteger(hexString: eHexString)

        // Create BoringSSL RSA key.
        guard let rsaPtr = n.withUnsafeBignumPointer({ n in
            e.withUnsafeBignumPointer { e in
                CCryptoBoringSSL_RSA_new_public_key(n, e)
            }
        }) else { throw CryptoKitError.internalBoringSSLError() }
        defer { CCryptoBoringSSL_RSA_free(rsaPtr) }

        // Get PEM representation for key.
        let pemRepresentation = BIOHelper.withWritableMemoryBIO { bio in
            precondition(CCryptoBoringSSL_PEM_write_bio_RSAPublicKey(bio, rsaPtr) == 1)
            return try! String(copyingUTF8MemoryBIO: bio)
        }

        // Create a key (which might be backed by Security framework) from PEM representation.
        try self.init(pemRepresentation: pemRepresentation, parameters: parameters)
    }
}


extension _RSA.BlindSigning.PrivateKey {
    /// Construct a platform-specific RSA private key with the specified parameters.
    ///
    /// This constructor is used in tests in cases where test vectors provide the key information this way.
    ///
    /// Only the BoringSSL backend provides APIs to create the key from its parameters so we first create a BoringSSL
    /// key, serialize it to PEM format, and then construct a platform specific key from the PEM representation.
    internal init(nHexString: String, eHexString: String, dHexString: String, pHexString: String, qHexString: String, parameters: Parameters) throws {
        let n = try ArbitraryPrecisionInteger(hexString: nHexString)
        let e = try ArbitraryPrecisionInteger(hexString: eHexString)
        let d = try ArbitraryPrecisionInteger(hexString: dHexString)
        let p = try ArbitraryPrecisionInteger(hexString: pHexString)
        let q = try ArbitraryPrecisionInteger(hexString: qHexString)

        // Compute the CRT params.
        let dp = try FiniteFieldArithmeticContext(fieldSize: p - 1).residue(d)
        let dq = try FiniteFieldArithmeticContext(fieldSize: q - 1).residue(d)
        guard let qi = try FiniteFieldArithmeticContext(fieldSize: p).inverse(q) else {
            throw CryptoKitError.internalBoringSSLError()
        }

        // Create BoringSSL RSA key.
        guard let rsaPtr = n.withUnsafeBignumPointer({ n in
            e.withUnsafeBignumPointer { e in
                d.withUnsafeBignumPointer { d in
                    p.withUnsafeBignumPointer { p in
                        q.withUnsafeBignumPointer { q in
                            dp.withUnsafeBignumPointer { dp in
                                dq.withUnsafeBignumPointer { dq in
                                    qi.withUnsafeBignumPointer { qi in
                                        CCryptoBoringSSL_RSA_new_private_key(n, e, d, p, q, dp, dq, qi)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }) else { throw CryptoKitError.internalBoringSSLError() }
        defer { CCryptoBoringSSL_RSA_free(rsaPtr) }

        // Get PEM representation for key.
        let pemRepresentation = BIOHelper.withWritableMemoryBIO { bio in
            precondition(CCryptoBoringSSL_PEM_write_bio_RSAPrivateKey(bio, rsaPtr, nil, nil, 0, nil, nil) == 1)
            return try! String(copyingUTF8MemoryBIO: bio)
        }

        // Create a key (which might be backed by Security framework) from PEM representation.
        try self.init(pemRepresentation: pemRepresentation, parameters: parameters)
    }
}
