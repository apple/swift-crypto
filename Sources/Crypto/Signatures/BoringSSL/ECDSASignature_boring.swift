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

/// A wrapper around BoringSSL's ECDSA_SIG with some lifetime management.
class ECDSASignature {
    private var _baseSig: UnsafeMutablePointer<ECDSA_SIG>

    init<ContiguousBuffer: ContiguousBytes>(contiguousDERBytes derBytes: ContiguousBuffer) throws {
        self._baseSig = try derBytes.withUnsafeBytes { bytesPtr in
            guard let sig = CCryptoBoringSSLShims_ECDSA_SIG_from_bytes(bytesPtr.baseAddress, bytesPtr.count) else {
                throw CryptoKitError.internalBoringSSLError()
            }
            return sig
        }
    }

    @usableFromInline
    init(rawRepresentation: Data) throws {
        let half = rawRepresentation.count / 2
        let r = try ArbitraryPrecisionInteger(bytes: rawRepresentation.prefix(half))
        let s = try ArbitraryPrecisionInteger(bytes: rawRepresentation.suffix(half))
        guard let sig = CCryptoBoringSSL_ECDSA_SIG_new() else {
            throw CryptoKitError.internalBoringSSLError()
        }

        self._baseSig = sig

        try r.withUnsafeBignumPointer { rPtr in
            try s.withUnsafeBignumPointer { sPtr in
                // This call is awkward: on success it _takes ownership_ of both values, on failure it doesn't.
                // This means we need to dup the pointers (to get something the ECDSA_SIG can own) and then
                // on error we have to free them. This makes lifetime management pretty rough here!
                guard let rCopy = CCryptoBoringSSL_BN_dup(rPtr) else {
                    throw CryptoKitError.internalBoringSSLError()
                }
                guard let sCopy = CCryptoBoringSSL_BN_dup(sPtr) else {
                    CCryptoBoringSSL_BN_free(rCopy)
                    throw CryptoKitError.internalBoringSSLError()
                }

                let rc = CCryptoBoringSSL_ECDSA_SIG_set0(self._baseSig, rCopy, sCopy)
                if rc == 0 {
                    // Error. We still own the bignums, and must free them.
                    CCryptoBoringSSL_BN_free(rCopy)
                    CCryptoBoringSSL_BN_free(sCopy)
                }

                // Success. We don't own the bignums anymore and mustn't free them.
            }
        }
    }

    init(takingOwnershipOf pointer: UnsafeMutablePointer<ECDSA_SIG>) {
        self._baseSig = pointer
    }

    deinit {
        CCryptoBoringSSL_ECDSA_SIG_free(self._baseSig)
    }

    @usableFromInline
    var components: (r: ArbitraryPrecisionInteger, s: ArbitraryPrecisionInteger) {
        var rPtr: UnsafePointer<BIGNUM>?
        var sPtr: UnsafePointer<BIGNUM>?

        // We force-unwrap here because a valid ECDSA_SIG cannot fail to have both R and S components.
        CCryptoBoringSSL_ECDSA_SIG_get0(self._baseSig, &rPtr, &sPtr)
        return (r: try! ArbitraryPrecisionInteger(copying: rPtr!), s: try! ArbitraryPrecisionInteger(copying: sPtr!))
    }

    @usableFromInline
    var derBytes: Data {
        var dataPtr: UnsafeMutablePointer<UInt8>?
        var length = 0
        guard CCryptoBoringSSL_ECDSA_SIG_to_bytes(&dataPtr, &length, self._baseSig) == 1 else {
            fatalError("Unable to marshal signature to DER")
        }
        defer {
            // We must free this pointer.
            CCryptoBoringSSL_OPENSSL_free(dataPtr)
        }

        return Data(UnsafeBufferPointer(start: dataPtr, count: length))
    }

    func withUnsafeSignaturePointer<T>(_ body: (UnsafeMutablePointer<ECDSA_SIG>) throws -> T) rethrows -> T {
        return try body(self._baseSig)
    }
}
