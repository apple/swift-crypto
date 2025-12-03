//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// NOTE: This file is unconditionally compiled because RSABSSA is implemented using BoringSSL on all platforms.
@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims
import Crypto
import CryptoBoringWrapper

#if canImport(FoundationEssentials)
#if os(Windows)
import ucrt
#elseif canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Android)
import Android
#elseif canImport(WASILibc)
import WASILibc
#endif
import FoundationEssentials
#else
import Foundation
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
internal struct BoringSSLRSAPublicKey: Sendable {
    private var backing: Backing

    init(pemRepresentation: String) throws {
        self.backing = try Backing(pemRepresentation: pemRepresentation)
    }

    init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
        self.backing = try Backing(derRepresentation: derRepresentation)
    }

    init(n: some ContiguousBytes, e: some ContiguousBytes) throws {
        self.backing = try Backing(n: n, e: e)
    }

    init(_ other: BoringSSLRSAPublicKey) throws {
        self = other
    }

    var pkcs1DERRepresentation: Data {
        self.backing.pkcs1DERRepresentation
    }

    var pkcs1PEMRepresentation: String {
        self.backing.pkcs1PEMRepresentation
    }

    var derRepresentation: Data {
        self.backing.derRepresentation
    }

    var pemRepresentation: String {
        self.backing.pemRepresentation
    }

    var keySizeInBits: Int {
        self.backing.keySizeInBits
    }

    fileprivate init(_ backing: Backing) {
        self.backing = backing
    }

    func getKeyPrimitives() -> (n: Data, e: Data) {
        self.backing.getKeyPrimitives()
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
internal struct BoringSSLRSAPrivateKey: Sendable {
    private var backing: Backing

    init(pemRepresentation: String) throws {
        self.backing = try Backing(pemRepresentation: pemRepresentation)
    }

    init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
        self.backing = try Backing(derRepresentation: derRepresentation)
    }

    init(
        n: some ContiguousBytes,
        e: some ContiguousBytes,
        d: some ContiguousBytes,
        p: some ContiguousBytes,
        q: some ContiguousBytes
    ) throws {
        self.backing = try Backing(n: n, e: e, d: d, p: p, q: q)
    }

    init(_ other: BoringSSLRSAPrivateKey) throws {
        self = other
    }

    init(keySize: _RSA.Signing.KeySize) throws {
        self.backing = try Backing(keySize: keySize)
    }

    var derRepresentation: Data {
        self.backing.derRepresentation
    }

    var pemRepresentation: String {
        self.backing.pemRepresentation
    }

    var pkcs8DERRepresentation: Data {
        self.backing.pkcs8DERRepresentation
    }

    var pkcs8PEMRepresentation: String {
        self.backing.pkcs8PEMRepresentation
    }

    var keySizeInBits: Int {
        self.backing.keySizeInBits
    }

    var publicKey: BoringSSLRSAPublicKey {
        self.backing.publicKey
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLRSAPrivateKey {
    internal func signature<D: Digest>(
        for digest: D,
        padding: _RSA.Signing.Padding
    ) throws
        -> _RSA.Signing.RSASignature
    {
        try self.backing.signature(for: digest, padding: padding)
    }

    internal func decrypt<D: DataProtocol>(_ data: D, padding: _RSA.Encryption.Padding) throws -> Data {
        try self.backing.decrypt(data, padding: padding)
    }

    internal func blindSignature<D: DataProtocol>(
        for message: D
    ) throws
        -> _RSA.BlindSigning.BlindSignature
    {
        try self.backing.blindSignature(for: message)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLRSAPublicKey {
    func isValidSignature<D: Digest>(
        _ signature: _RSA.Signing.RSASignature,
        for digest: D,
        padding: _RSA.Signing.Padding
    ) -> Bool {
        self.backing.isValidSignature(signature, for: digest, padding: padding)
    }

    internal func encrypt<D: DataProtocol>(_ data: D, padding: _RSA.Encryption.Padding) throws -> Data {
        try self.backing.encrypt(data, padding: padding)
    }

    internal func blind<H: HashFunction>(
        _ message: _RSA.BlindSigning.PreparedMessage,
        parameters: _RSA.BlindSigning.Parameters<H>
    ) throws -> _RSA.BlindSigning.BlindingResult {
        try self.backing.blind(message, parameters: parameters)
    }

    internal func finalize<H: HashFunction>(
        _ signature: _RSA.BlindSigning.BlindSignature,
        for message: _RSA.BlindSigning.PreparedMessage,
        blindingInverse: _RSA.BlindSigning.BlindingInverse,
        parameters: _RSA.BlindSigning.Parameters<H>
    ) throws -> _RSA.Signing.RSASignature {
        try self.backing.finalize(
            signature,
            for: message,
            blindingInverse: blindingInverse,
            parameters: parameters
        )
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLRSAPublicKey {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    fileprivate final class Backing: @unchecked Sendable {
        private let pointer: OpaquePointer

        fileprivate init(takingOwnershipOf pointer: OpaquePointer) {
            self.pointer = pointer
        }

        fileprivate init(copying other: Backing) {
            self.pointer = CCryptoBoringSSL_EVP_PKEY_new()
            let rsaPublicKey = CCryptoBoringSSL_RSAPublicKey_dup(
                CCryptoBoringSSL_EVP_PKEY_get0_RSA(other.pointer)
            )
            CCryptoBoringSSL_EVP_PKEY_assign_RSA(self.pointer, rsaPublicKey)
        }

        fileprivate init(pemRepresentation: String) throws {
            var pemRepresentation = pemRepresentation
            self.pointer = CCryptoBoringSSL_EVP_PKEY_new()

            // There are two encodings for RSA public keys: PKCS#1 and the SPKI form.
            // The SPKI form is what we support for EC keys, so we try that first, then we
            // fall back to the PKCS#1 form if that parse fails.
            do {
                let rsaPublicKey = try pemRepresentation.withUTF8 { utf8Ptr in
                    try BIOHelper.withReadOnlyMemoryBIO(wrapping: utf8Ptr) { bio in
                        guard let key = CCryptoBoringSSL_PEM_read_bio_RSA_PUBKEY(bio, nil, nil, nil) else {
                            throw CryptoKitError.internalBoringSSLError()
                        }
                        return key
                    }
                }
                CCryptoBoringSSL_EVP_PKEY_assign_RSA(self.pointer, rsaPublicKey)
            } catch {
                do {
                    let rsaPublicKey = try pemRepresentation.withUTF8 { utf8Ptr in
                        try BIOHelper.withReadOnlyMemoryBIO(wrapping: utf8Ptr) { bio in
                            guard let key = CCryptoBoringSSL_PEM_read_bio_RSAPublicKey(bio, nil, nil, nil) else {
                                throw CryptoKitError.internalBoringSSLError()
                            }
                            return key
                        }
                    }
                    CCryptoBoringSSL_EVP_PKEY_assign_RSA(self.pointer, rsaPublicKey)
                } catch {
                    CCryptoBoringSSL_EVP_PKEY_free(self.pointer)
                    throw error
                }
            }
        }

        fileprivate convenience init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
            if derRepresentation.regions.count == 1 {
                try self.init(contiguousDerRepresentation: derRepresentation.regions.first!)
            } else {
                let flattened = Array(derRepresentation)
                try self.init(contiguousDerRepresentation: flattened)
            }
        }

        private init<Bytes: ContiguousBytes>(contiguousDerRepresentation: Bytes) throws {
            self.pointer = CCryptoBoringSSL_EVP_PKEY_new()
            // There are two encodings for RSA public keys: PKCS#1 and the SPKI form.
            // The SPKI form is what we support for EC keys, so we try that first, then we
            // fall back to the PKCS#1 form if that parse fails.
            do {
                let rsaPublicKey = try contiguousDerRepresentation.withUnsafeBytes { derPtr in
                    try BIOHelper.withReadOnlyMemoryBIO(wrapping: derPtr) { bio in
                        guard let key = CCryptoBoringSSL_d2i_RSA_PUBKEY_bio(bio, nil) else {
                            throw CryptoKitError.internalBoringSSLError()
                        }
                        return key
                    }
                }
                CCryptoBoringSSL_EVP_PKEY_assign_RSA(self.pointer, rsaPublicKey)
            } catch {
                do {
                    let rsaPublicKey = try contiguousDerRepresentation.withUnsafeBytes { derPtr in
                        try BIOHelper.withReadOnlyMemoryBIO(wrapping: derPtr) { bio in
                            guard let key = CCryptoBoringSSL_d2i_RSAPublicKey_bio(bio, nil) else {
                                throw CryptoKitError.internalBoringSSLError()
                            }
                            return key
                        }
                    }
                    CCryptoBoringSSL_EVP_PKEY_assign_RSA(self.pointer, rsaPublicKey)
                } catch {
                    CCryptoBoringSSL_EVP_PKEY_free(self.pointer)
                    throw error
                }
            }
        }

        fileprivate init(n: some ContiguousBytes, e: some ContiguousBytes) throws {
            self.pointer = CCryptoBoringSSL_EVP_PKEY_new()
            let n = try ArbitraryPrecisionInteger(bytes: n)
            let e = try ArbitraryPrecisionInteger(bytes: e)

            // Create BoringSSL RSA key.
            guard
                let rsaPtr = n.withUnsafeBignumPointer({ n in
                    e.withUnsafeBignumPointer { e in
                        CCryptoBoringSSL_RSA_new_public_key(n, e)
                    }
                })
            else { throw CryptoKitError.internalBoringSSLError() }
            CCryptoBoringSSL_EVP_PKEY_assign_RSA(self.pointer, rsaPtr)
        }

        fileprivate var pkcs1DERRepresentation: Data {
            BIOHelper.withWritableMemoryBIO { bio in
                let rsaPublicKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
                let rc = CCryptoBoringSSL_i2d_RSAPublicKey_bio(bio, rsaPublicKey)
                precondition(rc == 1)

                return try! Data(copyingMemoryBIO: bio)
            }
        }

        fileprivate var pkcs1PEMRepresentation: String {
            ASN1.PEMDocument(type: _RSA.PKCS1PublicKeyType, derBytes: self.pkcs1DERRepresentation)
                .pemString
        }

        fileprivate var derRepresentation: Data {
            BIOHelper.withWritableMemoryBIO { bio in
                let rsaPublicKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
                let rc = CCryptoBoringSSL_i2d_RSA_PUBKEY_bio(bio, rsaPublicKey)
                precondition(rc == 1)

                return try! Data(copyingMemoryBIO: bio)
            }
        }

        fileprivate var pemRepresentation: String {
            ASN1.PEMDocument(type: _RSA.SPKIPublicKeyType, derBytes: self.derRepresentation)
                .pemString
        }

        fileprivate var keySizeInBits: Int {
            let rsaPublicKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
            return Int(CCryptoBoringSSL_RSA_size(rsaPublicKey)) * 8
        }

        fileprivate func isValidSignature<D: Digest>(
            _ signature: _RSA.Signing.RSASignature,
            for digest: D,
            padding: _RSA.Signing.Padding
        ) -> Bool {
            let hashDigestType = try! DigestType(forDigestType: D.self)
            let rsaPublicKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)

            return signature.withUnsafeBytes { signaturePtr in
                let rc: CInt = digest.withUnsafeBytes { digestPtr in
                    switch padding.backing {
                    case .pkcs1v1_5:
                        return CCryptoBoringSSLShims_RSA_verify(
                            hashDigestType.nid,
                            digestPtr.baseAddress,
                            digestPtr.count,
                            signaturePtr.baseAddress,
                            signaturePtr.count,
                            rsaPublicKey
                        )
                    case .pss:
                        return CCryptoBoringSSLShims_RSA_verify_pss_mgf1(
                            rsaPublicKey,
                            digestPtr.baseAddress,
                            digestPtr.count,
                            hashDigestType.dispatchTable,
                            hashDigestType.dispatchTable,
                            CInt(hashDigestType.digestLength),
                            signaturePtr.baseAddress,
                            signaturePtr.count
                        )
                    case .pssZero:
                        return CCryptoBoringSSLShims_RSA_verify_pss_mgf1(
                            rsaPublicKey,
                            digestPtr.baseAddress,
                            digestPtr.count,
                            hashDigestType.dispatchTable,
                            hashDigestType.dispatchTable,
                            CInt(0),
                            signaturePtr.baseAddress,
                            signaturePtr.count
                        )
                    }
                }
                return rc == 1
            }
        }

        fileprivate func encrypt<D: DataProtocol>(
            _ data: D,
            padding: _RSA.Encryption.Padding
        ) throws
            -> Data
        {
            let rsaPublicKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
            let outputSize = Int(CCryptoBoringSSL_RSA_size(rsaPublicKey))
            var output = Data(count: outputSize)

            let contiguousData: ContiguousBytes =
                data.regions.count == 1 ? data.regions.first! : Array(data)
            try output.withUnsafeMutableBytes { bufferPtr in
                try contiguousData.withUnsafeBytes { dataPtr in
                    // `nil` 'engine' defaults to the standard implementation with no hooks
                    let ctx = CCryptoBoringSSL_EVP_PKEY_CTX_new(self.pointer, nil)
                    defer {
                        CCryptoBoringSSL_EVP_PKEY_CTX_free(ctx)
                    }

                    CCryptoBoringSSL_EVP_PKEY_encrypt_init(ctx)

                    switch padding.backing {
                    case ._weakAndInsecure_pkcs1v1_5:
                        CCryptoBoringSSL_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING)
                    case let .pkcs1_oaep(digest):
                        CCryptoBoringSSL_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING)
                        switch digest {
                        case .sha1:
                            break  // default case, nothing to set
                        case .sha256:
                            CCryptoBoringSSL_EVP_PKEY_CTX_set_rsa_oaep_md(ctx, CCryptoBoringSSL_EVP_sha256())
                        }
                    }

                    var writtenLength = bufferPtr.count
                    let rc = CCryptoBoringSSLShims_EVP_PKEY_encrypt(
                        ctx,
                        bufferPtr.baseAddress,
                        &writtenLength,
                        dataPtr.baseAddress,
                        dataPtr.count
                    )
                    precondition(
                        writtenLength == bufferPtr.count,
                        "PKEY encrypt actual written length should match RSA key size."
                    )

                    guard rc == 1 else {
                        throw CryptoKitError.internalBoringSSLError()
                    }
                }
            }
            return output
        }

        fileprivate func blind<H: HashFunction>(
            _ message: _RSA.BlindSigning.PreparedMessage,
            parameters: _RSA.BlindSigning.Parameters<H>
        ) throws -> _RSA.BlindSigning.BlindingResult {
            let rsaPublicKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
            let modulusByteCount = Int(CCryptoBoringSSL_RSA_size(rsaPublicKey))
            let e = try ArbitraryPrecisionInteger(copying: CCryptoBoringSSL_RSA_get0_e(rsaPublicKey))
            let n = try ArbitraryPrecisionInteger(copying: CCryptoBoringSSL_RSA_get0_n(rsaPublicKey))
            let finiteField = try FiniteFieldArithmeticContext(fieldSize: n)

            // 1. encoded_msg = EMSA-PSS-ENCODE(msg, bit_len(n)) with Hash, MGF, and salt_len as defined in the parameters
            // 2. If EMSA-PSS-ENCODE raises an error, re-raise the error and stop
            // 3. m = bytes_to_int(encoded_msg)
            let m = try BlindSigningHelpers.EMSAPSSEncode(
                rsaPublicKey: rsaPublicKey,
                modulusByteCount: modulusByteCount,
                message: message,
                parameters: parameters
            )

            // 4. c = is_coprime(m, n)
            let c = try m.isCoprime(with: n)

            // 5. If c is false, raise an "invalid input" error and stop
            if !c { throw CryptoKitError(_RSA.BlindSigning.ProtocolError.invalidInput) }

            // 6. r = random_integer_uniform(1, n)
            // 7. inv = inverse_mod(r, n)
            // 8. If inverse_mod fails, raise a "blinding error" error and stop
            // NOTE: We retry here until we get an appropriate r, which is suggested.
            var r: ArbitraryPrecisionInteger
            var inv: ArbitraryPrecisionInteger!
            repeat {
                r = try ArbitraryPrecisionInteger.random(inclusiveMin: 1, exclusiveMax: n)
                inv = try finiteField.inverse(r)
            } while inv == nil

            // 9. x = RSAVP1(pk, r)
            let x = try finiteField.pow(secret: r, e)

            // 10. z = (m * x) mod n
            let z = try finiteField.multiply(m, x)

            // 11. blinded_msg = int_to_bytes(z, modulus_len)
            let blindedMessage = try Data(bytesOf: z, paddedToSize: modulusByteCount)

            // 12. output blinded_msg, inv
            let blindingInverse = _RSA.BlindSigning.BlindingInverse(
                rawRepresentation: try Data(bytesOf: inv, paddedToSize: modulusByteCount)
            )
            return _RSA.BlindSigning.BlindingResult(
                blindedMessage: blindedMessage,
                inverse: blindingInverse
            )
        }

        fileprivate func finalize<H: HashFunction>(
            _ blindSignature: _RSA.BlindSigning.BlindSignature,
            for message: _RSA.BlindSigning.PreparedMessage,
            blindingInverse: _RSA.BlindSigning.BlindingInverse,
            parameters: _RSA.BlindSigning.Parameters<H>
        ) throws -> _RSA.Signing.RSASignature {
            let rsaPublicKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
            let modulusByteCount = Int(CCryptoBoringSSL_RSA_size(rsaPublicKey))
            let n = try ArbitraryPrecisionInteger(copying: CCryptoBoringSSL_RSA_get0_n(rsaPublicKey))
            let finiteField = try FiniteFieldArithmeticContext(fieldSize: n)

            // 1. If len(blind_sig) != modulus_len, raise an "unexpected input size" error and stop
            guard blindSignature.rawRepresentation.count == modulusByteCount else {
                throw CryptoKitError(_RSA.BlindSigning.ProtocolError.unexpectedInputSize)
            }

            // 2. z = bytes_to_int(blind_sig)
            let z = try ArbitraryPrecisionInteger(bytes: blindSignature.rawRepresentation)

            // 3. s = (z * inv) mod n
            let inv = try ArbitraryPrecisionInteger(bytes: blindingInverse.rawRepresentation)
            let s = try finiteField.multiply(z, inv)

            // 4. sig = int_to_bytes(s, modulus_len)
            let sig = _RSA.Signing.RSASignature(
                rawRepresentation: try Data(bytesOf: s, paddedToSize: modulusByteCount)
            )

            // 5. result = RSASSA-PSS-VERIFY(pk, msg, sig) with Hash, MGF, and salt_len as defined in the parameters
            let result = try BlindSigningHelpers.RSASSAPSSVerify(
                rsaPublicKey: rsaPublicKey,
                modulusByteCount: modulusByteCount,
                message: message,
                signature: sig,
                parameters: parameters
            )

            // 6. If result = "valid signature", output sig, else raise an "invalid signature" error and stop
            if result {
                return sig
            } else {
                throw CryptoKitError(_RSA.BlindSigning.ProtocolError.invalidSignature)
            }
        }

        deinit {
            CCryptoBoringSSL_EVP_PKEY_free(self.pointer)
        }

        fileprivate func getKeyPrimitives() -> (n: Data, e: Data) {
            let key = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)

            func getPrimitive(_ getPointer: (OpaquePointer?) -> UnsafePointer<BIGNUM>?) -> Data {
                let ptr = getPointer(key)
                let size = Int(CCryptoBoringSSL_BN_num_bytes(ptr))
                var data = Data(count: size)
                data.withUnsafeMutableBytes { dataPtr in
                    _ = CCryptoBoringSSL_BN_bn2bin(ptr, dataPtr.baseAddress)
                }
                return data
            }

            return (getPrimitive(CCryptoBoringSSL_RSA_get0_n), getPrimitive(CCryptoBoringSSL_RSA_get0_e))
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLRSAPrivateKey {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    fileprivate final class Backing: @unchecked Sendable {
        private let pointer: OpaquePointer

        fileprivate init(copying other: Backing) {
            self.pointer = CCryptoBoringSSL_EVP_PKEY_new()
            let rsaPrivateKey = CCryptoBoringSSL_RSAPrivateKey_dup(
                CCryptoBoringSSL_EVP_PKEY_get0_RSA(other.pointer)
            )
            CCryptoBoringSSL_EVP_PKEY_assign_RSA(self.pointer, rsaPrivateKey)
        }

        fileprivate init(pemRepresentation: String) throws {
            var pemRepresentation = pemRepresentation
            self.pointer = CCryptoBoringSSL_EVP_PKEY_new()

            let rsaPrivateKey = try pemRepresentation.withUTF8 { utf8Ptr in
                try BIOHelper.withReadOnlyMemoryBIO(wrapping: utf8Ptr) { bio in
                    guard let key = CCryptoBoringSSL_PEM_read_bio_RSAPrivateKey(bio, nil, nil, nil) else {
                        throw CryptoKitError.internalBoringSSLError()
                    }

                    return key
                }
            }
            CCryptoBoringSSL_EVP_PKEY_assign_RSA(self.pointer, rsaPrivateKey)
        }

        fileprivate convenience init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
            if derRepresentation.regions.count == 1 {
                try self.init(contiguousDerRepresentation: derRepresentation.regions.first!)
            } else {
                let flattened = Array(derRepresentation)
                try self.init(contiguousDerRepresentation: flattened)
            }
        }

        private init<Bytes: ContiguousBytes>(contiguousDerRepresentation: Bytes) throws {
            self.pointer = CCryptoBoringSSL_EVP_PKEY_new()
            let rsaPrivateKey: OpaquePointer
            if let pointer = Backing.pkcs8DERPrivateKey(contiguousDerRepresentation) {
                rsaPrivateKey = pointer
            } else if let pointer = Backing.pkcs1DERPrivateKey(contiguousDerRepresentation) {
                rsaPrivateKey = pointer
            } else {
                throw CryptoKitError.internalBoringSSLError()
            }
            CCryptoBoringSSL_EVP_PKEY_assign_RSA(self.pointer, rsaPrivateKey)
        }

        fileprivate init(
            n: some ContiguousBytes,
            e: some ContiguousBytes,
            d: some ContiguousBytes,
            p: some ContiguousBytes,
            q: some ContiguousBytes
        ) throws {
            self.pointer = CCryptoBoringSSL_EVP_PKEY_new()
            let n = try ArbitraryPrecisionInteger(bytes: n)
            let e = try ArbitraryPrecisionInteger(bytes: e)
            let d = try ArbitraryPrecisionInteger(bytes: d)
            let p = try ArbitraryPrecisionInteger(bytes: p)
            let q = try ArbitraryPrecisionInteger(bytes: q)

            // Compute the CRT params.
            let dp = try FiniteFieldArithmeticContext(fieldSize: p - 1).residue(d)
            let dq = try FiniteFieldArithmeticContext(fieldSize: q - 1).residue(d)
            guard let qi = try FiniteFieldArithmeticContext(fieldSize: p).inverse(q) else {
                throw CryptoKitError.internalBoringSSLError()
            }

            // Create BoringSSL RSA key.
            guard
                let rsaPtr = n.withUnsafeBignumPointer({ n in
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
                })
            else { throw CryptoKitError.internalBoringSSLError() }
            CCryptoBoringSSL_EVP_PKEY_assign_RSA(self.pointer, rsaPtr)
        }

        private static func pkcs8DERPrivateKey<Bytes: ContiguousBytes>(
            _ derRepresentation: Bytes
        )
            -> OpaquePointer?
        {
            derRepresentation.withUnsafeBytes { derPtr in
                BIOHelper.withReadOnlyMemoryBIO(wrapping: derPtr) { bio in
                    guard let p8 = CCryptoBoringSSL_d2i_PKCS8_PRIV_KEY_INFO_bio(bio, nil) else {
                        return nil
                    }
                    defer {
                        CCryptoBoringSSL_PKCS8_PRIV_KEY_INFO_free(p8)
                    }

                    guard let pkey = CCryptoBoringSSL_EVP_PKCS82PKEY(p8) else {
                        return nil
                    }
                    defer {
                        CCryptoBoringSSL_EVP_PKEY_free(pkey)
                    }
                    return CCryptoBoringSSL_EVP_PKEY_get1_RSA(pkey)
                }
            }
        }

        private static func pkcs1DERPrivateKey<Bytes: ContiguousBytes>(
            _ derRepresentation: Bytes
        )
            -> OpaquePointer?
        {
            derRepresentation.withUnsafeBytes { derPtr in
                BIOHelper.withReadOnlyMemoryBIO(wrapping: derPtr) { bio in
                    CCryptoBoringSSL_d2i_RSAPrivateKey_bio(bio, nil)
                }
            }
        }

        fileprivate init(keySize: _RSA.Signing.KeySize) throws {
            let pointer = CCryptoBoringSSL_RSA_new()!

            // This do block is used to avoid the risk of leaking the above pointer.
            do {
                let rc = RSA_F4.withBignumPointer { bignumPtr in
                    CCryptoBoringSSL_RSA_generate_key_ex(
                        pointer,
                        CInt(keySize.bitCount),
                        bignumPtr,
                        nil
                    )
                }

                guard rc == 1 else {
                    throw CryptoKitError.internalBoringSSLError()
                }

                self.pointer = CCryptoBoringSSL_EVP_PKEY_new()
                CCryptoBoringSSL_EVP_PKEY_assign_RSA(self.pointer, pointer)
            } catch {
                CCryptoBoringSSL_RSA_free(pointer)
                throw error
            }
        }

        fileprivate var derRepresentation: Data {
            BIOHelper.withWritableMemoryBIO { bio in
                let rsaPrivateKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
                let rc = CCryptoBoringSSL_i2d_RSAPrivateKey_bio(bio, rsaPrivateKey)
                precondition(rc == 1)

                return try! Data(copyingMemoryBIO: bio)
            }
        }

        fileprivate var pemRepresentation: String {
            BIOHelper.withWritableMemoryBIO { bio in
                let rsaPrivateKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
                let rc = CCryptoBoringSSL_PEM_write_bio_RSAPrivateKey(
                    bio,
                    rsaPrivateKey,
                    nil,
                    nil,
                    0,
                    nil,
                    nil
                )
                precondition(rc == 1)

                return try! String(copyingUTF8MemoryBIO: bio)
            }
        }

        fileprivate var pkcs8DERRepresentation: Data {
            BIOHelper.withWritableMemoryBIO { bio in
                let rc = CCryptoBoringSSL_i2d_PKCS8PrivateKeyInfo_bio(bio, self.pointer)
                precondition(rc == 1, "Exporting PKCS8 DER key failed")

                return try! Data(copyingMemoryBIO: bio)
            }
        }

        fileprivate var pkcs8PEMRepresentation: String {
            BIOHelper.withWritableMemoryBIO { bio in
                let evp = CCryptoBoringSSL_EVP_PKEY_new()
                defer {
                    CCryptoBoringSSL_EVP_PKEY_free(evp)
                }
                let rsaPrivateKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
                CCryptoBoringSSL_EVP_PKEY_set1_RSA(evp, rsaPrivateKey)
                let rc = CCryptoBoringSSL_PEM_write_bio_PKCS8PrivateKey(bio, evp, nil, nil, 0, nil, nil)
                precondition(rc == 1)

                return try! String(copyingUTF8MemoryBIO: bio)
            }
        }

        fileprivate var keySizeInBits: Int {
            let rsaPrivateKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
            return Int(CCryptoBoringSSL_RSA_size(rsaPrivateKey)) * 8
        }

        fileprivate var publicKey: BoringSSLRSAPublicKey {
            let pkey = CCryptoBoringSSL_EVP_PKEY_new()!
            let rsaPublicKey = CCryptoBoringSSL_RSAPublicKey_dup(
                CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
            )
            CCryptoBoringSSL_EVP_PKEY_assign_RSA(pkey, rsaPublicKey)
            let backing = BoringSSLRSAPublicKey.Backing(
                takingOwnershipOf: pkey
            )
            return BoringSSLRSAPublicKey(backing)
        }

        fileprivate func signature<D: Digest>(
            for digest: D,
            padding: _RSA.Signing.Padding
        ) throws
            -> _RSA.Signing.RSASignature
        {
            let rsaPrivateKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
            let hashDigestType = try DigestType(forDigestType: D.self)
            let outputSize = Int(CCryptoBoringSSL_RSA_size(rsaPrivateKey))

            let output = try [UInt8](unsafeUninitializedCapacity: outputSize) { bufferPtr, length in
                var outputLength = 0

                let rc: CInt = digest.withUnsafeBytes { digestPtr in
                    switch padding.backing {
                    case .pkcs1v1_5:
                        var writtenLength = CUnsignedInt(0)
                        let rc = CCryptoBoringSSLShims_RSA_sign(
                            hashDigestType.nid,
                            digestPtr.baseAddress,
                            CUnsignedInt(digestPtr.count),
                            bufferPtr.baseAddress,
                            &writtenLength,
                            rsaPrivateKey
                        )
                        outputLength = Int(writtenLength)
                        return rc
                    case .pss:
                        return CCryptoBoringSSLShims_RSA_sign_pss_mgf1(
                            rsaPrivateKey,
                            &outputLength,
                            bufferPtr.baseAddress,
                            bufferPtr.count,
                            digestPtr.baseAddress,
                            digestPtr.count,
                            hashDigestType.dispatchTable,
                            hashDigestType.dispatchTable,
                            CInt(hashDigestType.digestLength)
                        )
                    case .pssZero:
                        return CCryptoBoringSSLShims_RSA_sign_pss_mgf1(
                            rsaPrivateKey,
                            &outputLength,
                            bufferPtr.baseAddress,
                            bufferPtr.count,
                            digestPtr.baseAddress,
                            digestPtr.count,
                            hashDigestType.dispatchTable,
                            hashDigestType.dispatchTable,
                            CInt(0)
                        )
                    }
                }
                if rc != 1 {
                    throw CryptoKitError.internalBoringSSLError()
                }

                length = outputLength
            }
            return _RSA.Signing.RSASignature(signatureBytes: output)
        }

        fileprivate func decrypt<D: DataProtocol>(
            _ data: D,
            padding: _RSA.Encryption.Padding
        ) throws
            -> Data
        {
            let rsaPrivateKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
            let outputSize = Int(CCryptoBoringSSL_RSA_size(rsaPrivateKey))
            var output = Data(count: outputSize)

            let contiguousData: ContiguousBytes =
                data.regions.count == 1 ? data.regions.first! : Array(data)
            let writtenLength: CInt = try output.withUnsafeMutableBytes { bufferPtr in
                try contiguousData.withUnsafeBytes { dataPtr in
                    let ctx = CCryptoBoringSSL_EVP_PKEY_CTX_new(self.pointer, nil)
                    defer {
                        CCryptoBoringSSL_EVP_PKEY_CTX_free(ctx)
                    }

                    CCryptoBoringSSL_EVP_PKEY_decrypt_init(ctx)
                    switch padding.backing {
                    case ._weakAndInsecure_pkcs1v1_5:
                        CCryptoBoringSSL_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING)
                    case let .pkcs1_oaep(digest):
                        CCryptoBoringSSL_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING)
                        switch digest {
                        case .sha1:
                            break  // default case, nothing to set
                        case .sha256:
                            CCryptoBoringSSL_EVP_PKEY_CTX_set_rsa_oaep_md(ctx, CCryptoBoringSSL_EVP_sha256())
                        }
                    }

                    var writtenLength = bufferPtr.count

                    let rc = CCryptoBoringSSLShims_EVP_PKEY_decrypt(
                        ctx,
                        bufferPtr.baseAddress,
                        &writtenLength,
                        dataPtr.baseAddress,
                        dataPtr.count
                    )

                    guard rc == 1 else {
                        throw CryptoKitError.internalBoringSSLError()
                    }

                    return CInt(writtenLength)
                }
            }

            output.removeSubrange(
                output.index(output.startIndex, offsetBy: Int(writtenLength))..<output.endIndex
            )
            return output
        }

        fileprivate func blindSignature<D: DataProtocol>(
            for message: D
        ) throws
            -> _RSA.BlindSigning.BlindSignature
        {
            let rsaPrivateKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
            let signatureByteCount = Int(CCryptoBoringSSL_RSA_size(rsaPrivateKey))

            guard message.count == signatureByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            let messageBytes: ContiguousBytes =
                message.regions.count == 1 ? message.regions.first! : Array(message)

            let signature = try withUnsafeTemporaryAllocation(
                of: UInt8.self,
                capacity: signatureByteCount
            ) { signatureBufferPtr in
                try messageBytes.withUnsafeBytes { messageBufferPtr in
                    /// NOTE: BoringSSL promotes the use of `RSA_sign_raw` over `RSA_private_encrypt`.
                    var outputCount = 0
                    guard
                        CCryptoBoringSSL_RSA_sign_raw(
                            rsaPrivateKey,
                            &outputCount,
                            signatureBufferPtr.baseAddress,
                            signatureBufferPtr.count,
                            messageBufferPtr.baseAddress,
                            messageBufferPtr.count,
                            RSA_NO_PADDING
                        ) == 1
                    else {
                        switch CCryptoBoringSSL_ERR_GET_REASON(CCryptoBoringSSL_ERR_peek_last_error()) {
                        case RSA_R_DATA_TOO_LARGE_FOR_MODULUS:
                            throw CryptoKitError(_RSA.BlindSigning.ProtocolError.messageRepresentativeOutOfRange)
                        default:
                            throw CryptoKitError.internalBoringSSLError()
                        }
                    }
                    precondition(outputCount == signatureBufferPtr.count)
                }
                return _RSA.BlindSigning.BlindSignature(rawRepresentation: Data(signatureBufferPtr))
            }

            // NOTE: Verification is part of the specification.
            try self.verifyBlindSignature(signature, for: messageBytes)

            return signature
        }

        fileprivate func verifyBlindSignature<D: ContiguousBytes>(
            _ signature: _RSA.BlindSigning.BlindSignature,
            for blindedMessage: D
        ) throws {
            try signature.withUnsafeBytes { signatureBufferPtr in
                try blindedMessage.withUnsafeBytes { blindedMessageBufferPtr in
                    try withUnsafeTemporaryAllocation(byteCount: blindedMessageBufferPtr.count, alignment: 1) {
                        verificationBufferPtr in
                        let rsaPublicKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
                        var outputCount = 0
                        /// NOTE: BoringSSL promotes the use of `RSA_verify_raw` over `RSA_public_decrypt`.
                        guard
                            CCryptoBoringSSL_RSA_verify_raw(
                                rsaPublicKey,
                                &outputCount,
                                verificationBufferPtr.baseAddress,
                                verificationBufferPtr.count,
                                signatureBufferPtr.baseAddress,
                                signatureBufferPtr.count,
                                RSA_NO_PADDING
                            ) == 1
                        else {
                            throw CryptoKitError.internalBoringSSLError()
                        }
                        guard
                            outputCount == blindedMessageBufferPtr.count,
                            memcmp(
                                verificationBufferPtr.baseAddress!,
                                blindedMessageBufferPtr.baseAddress!,
                                blindedMessageBufferPtr.count
                            ) == 0
                        else {
                            throw CryptoKitError(_RSA.BlindSigning.ProtocolError.signingFailure)
                        }
                    }
                }
            }
        }

        deinit {
            CCryptoBoringSSL_EVP_PKEY_free(self.pointer)
        }
    }
}

/// This namespace enum just provides helper functions for some of the steps outlined in the RFC.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
enum BlindSigningHelpers {
    fileprivate static func RSASSAPSSVerify<H: HashFunction>(
        rsaPublicKey: OpaquePointer!,
        modulusByteCount: Int,
        message: _RSA.BlindSigning.PreparedMessage,
        signature: _RSA.Signing.RSASignature,
        parameters: _RSA.BlindSigning.Parameters<H>
    ) throws -> Bool {
        let hashDigestType = try DigestType(forDigestType: H.Digest.self)
        return H.hash(data: message.rawRepresentation).withUnsafeBytes { messageHashBufferPtr in
            withUnsafeTemporaryAllocation(byteCount: modulusByteCount, alignment: 1) {
                encodedMessageBufferPtr in
                signature.withUnsafeBytes { signatureBufferPtr in
                    var outputCount = 0
                    guard
                        /// NOTE: BoringSSL promotes the use of `RSA_verify_raw` over `RSA_public_decrypt`.
                        CCryptoBoringSSL_RSA_verify_raw(
                            rsaPublicKey,
                            &outputCount,
                            encodedMessageBufferPtr.baseAddress,
                            encodedMessageBufferPtr.count,
                            signatureBufferPtr.baseAddress,
                            signatureBufferPtr.count,
                            RSA_NO_PADDING
                        ) == 1,
                        outputCount == modulusByteCount,
                        CCryptoBoringSSL_RSA_verify_PKCS1_PSS_mgf1(
                            rsaPublicKey,
                            messageHashBufferPtr.baseAddress,
                            hashDigestType.dispatchTable,
                            hashDigestType.dispatchTable,
                            encodedMessageBufferPtr.baseAddress,
                            parameters.saltLength
                        ) == 1
                    else { return false }
                    return true
                }
            }
        }
    }

    fileprivate static func EMSAPSSEncode<H: HashFunction>(
        rsaPublicKey: OpaquePointer!,
        modulusByteCount: Int,
        message: _RSA.BlindSigning.PreparedMessage,
        parameters: _RSA.BlindSigning.Parameters<H>
    ) throws -> ArbitraryPrecisionInteger {
        try withUnsafeTemporaryAllocation(of: UInt8.self, capacity: modulusByteCount) {
            encodedMessageBufferPtr in
            let hashDigestType = try DigestType(forDigestType: H.Digest.self)
            guard
                H.hash(data: message.rawRepresentation).withUnsafeBytes({ hashBufferPtr in
                    CCryptoBoringSSL_RSA_padding_add_PKCS1_PSS_mgf1(
                        rsaPublicKey,
                        encodedMessageBufferPtr.baseAddress,
                        hashBufferPtr.baseAddress,
                        hashDigestType.dispatchTable,
                        hashDigestType.dispatchTable,
                        parameters.saltLength
                    )
                }) == 1
            else {
                switch CCryptoBoringSSL_ERR_GET_REASON(CCryptoBoringSSL_ERR_peek_last_error()) {
                case RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE:
                    throw CryptoKitError(_RSA.BlindSigning.ProtocolError.messageTooLong)
                default:
                    throw CryptoKitError.internalBoringSSLError()
                }
            }
            return try ArbitraryPrecisionInteger(bytes: encodedMessageBufferPtr)
        }
    }
}
