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
import Foundation
import Crypto

// NOTE: This file is unconditionally compiled because RSABSSA is implemented using BoringSSL on all platforms.
@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims

internal struct BoringSSLRSAPublicKey: Sendable {
    private var backing: Backing

    init(pemRepresentation: String) throws {
        self.backing = try Backing(pemRepresentation: pemRepresentation)
    }

    init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
        self.backing = try Backing(derRepresentation: derRepresentation)
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
}


internal struct BoringSSLRSAPrivateKey: Sendable {
    private var backing: Backing

    init(pemRepresentation: String) throws {
        self.backing = try Backing(pemRepresentation: pemRepresentation)
    }

    init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
        self.backing = try Backing(derRepresentation: derRepresentation)
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

extension BoringSSLRSAPrivateKey {
    internal func signature<D: Digest>(for digest: D, padding: _RSA.Signing.Padding) throws -> _RSA.Signing.RSASignature {
        return try self.backing.signature(for: digest, padding: padding)
    }
    
    internal func decrypt<D: DataProtocol>(_ data: D, padding: _RSA.Encryption.Padding) throws -> Data {
        return try self.backing.decrypt(data, padding: padding)
    }

    internal func blindSignature<D: DataProtocol>(for message: D) throws -> _RSA.BlindSigning.BlindSignature {
        return try self.backing.blindSignature(for: message)
    }
 }

extension BoringSSLRSAPublicKey {
    func isValidSignature<D: Digest>(_ signature: _RSA.Signing.RSASignature, for digest: D, padding: _RSA.Signing.Padding) -> Bool {
        return self.backing.isValidSignature(signature, for: digest, padding: padding)
    }
    
    internal func encrypt<D: DataProtocol>(_ data: D, padding: _RSA.Encryption.Padding) throws -> Data {
        return try self.backing.encrypt(data, padding: padding)
    }

    internal func blind<H: HashFunction>(
        _ message: _RSA.BlindSigning.PreparedMessage,
        parameters: _RSA.BlindSigning.Parameters<H>
    ) throws -> (blindedMessage: _RSA.BlindSigning.BlindedMessage, blindInverse: _RSA.BlindSigning.BlindInverse) {
        return try self.backing.blind(message, parameters: parameters)
    }

    internal func finalize<H: HashFunction>(
            _ signature: _RSA.BlindSigning.BlindSignature,
            for message: _RSA.BlindSigning.PreparedMessage,
            blindInverse: _RSA.BlindSigning.BlindInverse,
            parameters: _RSA.BlindSigning.Parameters<H>
    ) throws -> _RSA.Signing.RSASignature {
        return try self.backing.finalize(signature, for: message, blindInverse: blindInverse, parameters: parameters)
    }
}

extension BoringSSLRSAPublicKey {
    fileprivate final class Backing {
        private let pointer: OpaquePointer

        fileprivate init(takingOwnershipOf pointer: OpaquePointer) {
            self.pointer = pointer
        }

        fileprivate init(copying other: Backing) {
            self.pointer = CCryptoBoringSSL_EVP_PKEY_new()
            let rsaPublicKey = CCryptoBoringSSL_RSAPublicKey_dup(CCryptoBoringSSL_EVP_PKEY_get0_RSA(other.pointer))
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
                    return try BIOHelper.withReadOnlyMemoryBIO(wrapping: utf8Ptr) { bio in
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
                        return try BIOHelper.withReadOnlyMemoryBIO(wrapping: utf8Ptr) { bio in
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
                    return try BIOHelper.withReadOnlyMemoryBIO(wrapping: derPtr) { bio in
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
                        return try BIOHelper.withReadOnlyMemoryBIO(wrapping: derPtr) { bio in
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

        fileprivate var pkcs1DERRepresentation: Data {
            return BIOHelper.withWritableMemoryBIO { bio in
                let rsaPublicKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
                let rc = CCryptoBoringSSL_i2d_RSAPublicKey_bio(bio, rsaPublicKey)
                precondition(rc == 1)

                return try! Data(copyingMemoryBIO: bio)
            }
        }

        fileprivate var pkcs1PEMRepresentation: String {
            return ASN1.PEMDocument(type: _RSA.PKCS1PublicKeyType, derBytes: self.pkcs1DERRepresentation).pemString
        }

        fileprivate var derRepresentation: Data {
            return BIOHelper.withWritableMemoryBIO { bio in
                let rsaPublicKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
                let rc = CCryptoBoringSSL_i2d_RSA_PUBKEY_bio(bio, rsaPublicKey)
                precondition(rc == 1)

                return try! Data(copyingMemoryBIO: bio)
            }
        }

        fileprivate var pemRepresentation: String {
            return ASN1.PEMDocument(type: _RSA.SPKIPublicKeyType, derBytes: self.derRepresentation).pemString
        }

        fileprivate var keySizeInBits: Int {
            let rsaPublicKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
            return Int(CCryptoBoringSSL_RSA_size(rsaPublicKey)) * 8
        }

        fileprivate func isValidSignature<D: Digest>(_ signature: _RSA.Signing.RSASignature, for digest: D, padding: _RSA.Signing.Padding) -> Bool {
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
        
        fileprivate func encrypt<D: DataProtocol>(_ data: D, padding: _RSA.Encryption.Padding) throws -> Data {
            let rsaPublicKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
            let outputSize = Int(CCryptoBoringSSL_RSA_size(rsaPublicKey))
            var output = Data(count: outputSize)

            let contiguousData: ContiguousBytes = data.regions.count == 1 ? data.regions.first! : Array(data)
            try output.withUnsafeMutableBytes { bufferPtr in
                try contiguousData.withUnsafeBytes { dataPtr in
                    // `nil` 'engine' defaults to the standard implementation with no hooks
                    let ctx = CCryptoBoringSSL_EVP_PKEY_CTX_new(self.pointer, nil)
                    defer {
                        CCryptoBoringSSL_EVP_PKEY_CTX_free(ctx)
                    }

                    CCryptoBoringSSL_EVP_PKEY_encrypt_init(ctx)

                    switch padding.backing {
                    case let .pkcs1_oaep(digest):
                        CCryptoBoringSSL_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING)
                        switch digest {
                        case .sha1:
                            break // default case, nothing to set
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
                    precondition(writtenLength == bufferPtr.count, "PKEY encrypt actual written length should match RSA key size.")

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
        ) throws -> (blindedMessage: _RSA.BlindSigning.BlindedMessage, blindInverse: _RSA.BlindSigning.BlindInverse) {
            /// ```
            /// All BN_CTX_get() calls must be made before calling any other functions that use the ctx as an argument.
            /// ...
            /// BN_CTX_get() returns a pointer to the BIGNUM, or NULL on error. Once BN_CTX_get() has failed, the
            /// subsequent calls will return NULL as well, so it is sufficient to check the return value of the last
            /// BN_CTX_get() call.
            /// ```
            /// —— Extract from `man 3 BN_CTX_get`.
            let bnCtx = CCryptoBoringSSL_BN_CTX_new()
            CCryptoBoringSSL_BN_CTX_start(bnCtx)
            defer {
                CCryptoBoringSSL_BN_CTX_end(bnCtx)
                CCryptoBoringSSL_BN_CTX_free(bnCtx)
            }
            let m = CCryptoBoringSSL_BN_CTX_get(bnCtx)
            let gcd = CCryptoBoringSSL_BN_CTX_get(bnCtx)
            let r = CCryptoBoringSSL_BN_CTX_get(bnCtx)
            let inv = CCryptoBoringSSL_BN_CTX_get(bnCtx)
            let x = CCryptoBoringSSL_BN_CTX_get(bnCtx)
            let z = CCryptoBoringSSL_BN_CTX_get(bnCtx)
            guard z != nil else { throw CryptoKitError.internalBoringSSLError() }

            let rsaPublicKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
            let outputSize = Int(CCryptoBoringSSL_RSA_size(rsaPublicKey))

            // 1. encoded_msg = EMSA-PSS-ENCODE(msg, bit_len(n)) with Hash, MGF, and salt_len as defined in the parameters
            // 2. If EMSA-PSS-ENCODE raises an error, re-raise the error and stop
            let hashDigestType = try! DigestType(forDigestType: H.Digest.self)
            let hash = H.hash(data: message.rawRepresentation)
            let saltLength: Int32
            switch parameters.padding {
            case .PSS: saltLength = Int32(H.Digest.byteCount)
            case .PSSZERO: saltLength = 0
            }
            var encodedMessage = [UInt8](repeating: 0, count: outputSize)
            guard hash.withUnsafeBytes({ hashBufferPtr in
                CCryptoBoringSSL_RSA_padding_add_PKCS1_PSS_mgf1(
                    rsaPublicKey,
                    &encodedMessage,
                    hashBufferPtr.baseAddress,
                    hashDigestType.dispatchTable,
                    hashDigestType.dispatchTable,
                    saltLength
                )
            }) == 1 else {
                throw CryptoKitError.internalBoringSSLError()
            }

            // 3. m = bytes_to_int(encoded_msg)
            CCryptoBoringSSL_BN_bin2bn(&encodedMessage, encodedMessage.count, m)

            // 4. c = is_coprime(m, n)
            let n = CCryptoBoringSSL_RSA_get0_n(rsaPublicKey)
            CCryptoBoringSSL_BN_gcd(gcd, m, n, bnCtx)
            let c = CCryptoBoringSSL_BN_is_one(gcd) == 1

            // 5. If c is false, raise an "invalid input" error and stop
            guard c else {
                throw CryptoKitError.invalidParameter
            }

            // 6. r = random_integer_uniform(1, n)
            // 7. inv = inverse_mod(r, n)
            // 8. If inverse_mod fails, raise a "blinding error" error and stop
            // NOTE: We retry here until we get an appropriate r, which is suggested.
            repeat {
                guard CCryptoBoringSSL_BN_rand_range_ex(r, 1, n) == 1 else {
                    throw CryptoKitError.internalBoringSSLError()
                }
            } while (CCryptoBoringSSL_BN_mod_inverse(inv, r, n, bnCtx) == nil)

            // 9. x = RSAVP1(pk, r)
            let e = CCryptoBoringSSL_RSA_get0_e(rsaPublicKey)
            let montCtx = CCryptoBoringSSL_BN_MONT_CTX_new_for_modulus(n, bnCtx)
            defer { CCryptoBoringSSL_BN_MONT_CTX_free(montCtx) }
            guard CCryptoBoringSSL_BN_mod_exp_mont(x, r, e, n, bnCtx, montCtx) == 1 else {
                throw CryptoKitError.internalBoringSSLError()
            }

            // 10. z = (m * x) mod n
            guard CCryptoBoringSSL_BN_mod_mul(z, m, x, n, bnCtx) == 1 else {
                throw CryptoKitError.internalBoringSSLError()
            }

            // 11. blinded_msg = int_to_bytes(z, modulus_len)
            var blindedMessageBytes = [UInt8](repeating: 0, count: outputSize)
            guard CCryptoBoringSSL_BN_bn2bin_padded(&blindedMessageBytes, outputSize, z) == 1 else {
                throw CryptoKitError.internalBoringSSLError()
            }

            // 12. output blinded_msg, inv
            let blindedMessage = _RSA.BlindSigning.BlindedMessage(rawRepresentation: Data(blindedMessageBytes))
            var invBytes = [UInt8](repeating: 0, count: outputSize)
            guard CCryptoBoringSSL_BN_bn2bin_padded(&invBytes, outputSize, inv) == 1 else {
                throw CryptoKitError.internalBoringSSLError()
            }
            let blindInverse = _RSA.BlindSigning.BlindInverse(rawRepresentation: Data(invBytes))
            return (blindedMessage, blindInverse)
        }

        fileprivate func finalize<H: HashFunction>(
            _ signature: _RSA.BlindSigning.BlindSignature,
            for message: _RSA.BlindSigning.PreparedMessage,
            blindInverse: _RSA.BlindSigning.BlindInverse,
            parameters: _RSA.BlindSigning.Parameters<H>
        ) throws -> _RSA.Signing.RSASignature {
            /// ```
            /// All BN_CTX_get() calls must be made before calling any other functions that use the ctx as an argument.
            /// ...
            /// BN_CTX_get() returns a pointer to the BIGNUM, or NULL on error. Once BN_CTX_get() has failed, the
            /// subsequent calls will return NULL as well, so it is sufficient to check the return value of the last
            /// BN_CTX_get() call.
            /// ```
            /// —— Extract from `man 3 BN_CTX_get`.
            let bnCtx = CCryptoBoringSSL_BN_CTX_new()
            CCryptoBoringSSL_BN_CTX_start(bnCtx)
            defer {
                CCryptoBoringSSL_BN_CTX_end(bnCtx)
                CCryptoBoringSSL_BN_CTX_free(bnCtx)
            }
            let z = CCryptoBoringSSL_BN_CTX_get(bnCtx)
            let inv = CCryptoBoringSSL_BN_CTX_get(bnCtx)
            let s = CCryptoBoringSSL_BN_CTX_get(bnCtx)
            guard s != nil else { throw CryptoKitError.internalBoringSSLError() }

            let rsaPublicKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
            let outputSize = Int(CCryptoBoringSSL_RSA_size(rsaPublicKey))

            // 1. If len(blind_sig) != modulus_len, raise an "unexpected input size" error and stop
            guard signature.rawRepresentation.count == outputSize else {
                throw CryptoKitError.invalidParameter
            }

            // 2. z = bytes_to_int(blind_sig)
            try signature.rawRepresentation.withUnsafeBytes { blindSignatureBytesPtr in
                guard CCryptoBoringSSLShims_BN_bin2bn(blindSignatureBytesPtr.baseAddress, blindSignatureBytesPtr.count, z) == z else {
                    throw CryptoKitError.internalBoringSSLError()
                }
            }

            // 3. s = (z * inv) mod n
            try blindInverse.rawRepresentation.withUnsafeBytes { blindInverseBytesPtr in
                guard CCryptoBoringSSLShims_BN_bin2bn(blindInverseBytesPtr.baseAddress, blindInverseBytesPtr.count, inv) == inv else {
                    throw CryptoKitError.internalBoringSSLError()
                }
            }
            let n = CCryptoBoringSSL_RSA_get0_n(rsaPublicKey)
            guard CCryptoBoringSSL_BN_mod_mul(s, z, inv, n, bnCtx) == 1 else {
                throw CryptoKitError.internalBoringSSLError()
            }

            // 4. sig = int_to_bytes(s, modulus_len)
            var sigBytes = [UInt8](repeating: 0, count: outputSize)
            guard CCryptoBoringSSL_BN_bn2bin_padded(&sigBytes, outputSize, s) == 1 else {
                throw CryptoKitError.internalBoringSSLError()
            }

            // 5. result = RSASSA-PSS-VERIFY(pk, msg, sig) with Hash, MGF, and salt_len as defined in the parameters
            try sigBytes.withUnsafeBufferPointer { signatureBufferPtr in
                try withUnsafeTemporaryAllocation(byteCount: outputSize, alignment: 1) { encodedMessageBufferPtr in
                    var outputCount = 0
                    /// NOTE: BoringSSL promotes the use of `RSA_verify_raw` over `RSA_public_decrypt`.
                    guard CCryptoBoringSSL_RSA_verify_raw(
                        rsaPublicKey,
                        &outputCount,
                        encodedMessageBufferPtr.baseAddress,
                        encodedMessageBufferPtr.count,
                        signatureBufferPtr.baseAddress,
                        signatureBufferPtr.count,
                        RSA_NO_PADDING
                    ) == 1 else {
                        throw CryptoKitError.internalBoringSSLError()
                    }
                    guard outputCount == outputSize else {
                        throw CryptoKitError.authenticationFailure
                    }
                    let hashDigestType = try DigestType(forDigestType: H.Digest.self)
                    let saltLength: Int32
                    switch parameters.padding {
                    case .PSS: saltLength = Int32(H.Digest.byteCount)
                    case .PSSZERO: saltLength = 0
                    }
                    try H.hash(data: message.rawRepresentation).withUnsafeBytes { messageHashBufferPtr in
                        guard CCryptoBoringSSL_RSA_verify_PKCS1_PSS_mgf1(
                            rsaPublicKey,
                            messageHashBufferPtr.baseAddress,
                            hashDigestType.dispatchTable,
                            hashDigestType.dispatchTable,
                            encodedMessageBufferPtr.baseAddress,
                            saltLength
                        ) == 1 else {
                            throw CryptoKitError.authenticationFailure
                        }
                    }
                }
            }

            // 6. If result = "valid signature", output sig, else raise an "invalid signature" error and stop
            return _RSA.Signing.RSASignature(signatureBytes: sigBytes)
        }
        deinit {
            CCryptoBoringSSL_EVP_PKEY_free(self.pointer)
        }
    }
}

extension BoringSSLRSAPrivateKey {
    fileprivate final class Backing {
        private let pointer: OpaquePointer

        fileprivate init(copying other: Backing) {
            self.pointer = CCryptoBoringSSL_EVP_PKEY_new()
            let rsaPrivateKey = CCryptoBoringSSL_RSAPrivateKey_dup(CCryptoBoringSSL_EVP_PKEY_get0_RSA(other.pointer))
            CCryptoBoringSSL_EVP_PKEY_assign_RSA(self.pointer, rsaPrivateKey)
        }

        fileprivate init(pemRepresentation: String) throws {
            var pemRepresentation = pemRepresentation
            self.pointer = CCryptoBoringSSL_EVP_PKEY_new()

            let rsaPrivateKey = try pemRepresentation.withUTF8 { utf8Ptr in
                return try BIOHelper.withReadOnlyMemoryBIO(wrapping: utf8Ptr) { bio in
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

        private static func pkcs8DERPrivateKey<Bytes: ContiguousBytes>(_ derRepresentation: Bytes) -> OpaquePointer? {
            return derRepresentation.withUnsafeBytes { derPtr in
                return BIOHelper.withReadOnlyMemoryBIO(wrapping: derPtr) { bio in
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

        private static func pkcs1DERPrivateKey<Bytes: ContiguousBytes>(_ derRepresentation: Bytes) -> OpaquePointer? {
            return derRepresentation.withUnsafeBytes { derPtr in
                return BIOHelper.withReadOnlyMemoryBIO(wrapping: derPtr) { bio in
                    return CCryptoBoringSSL_d2i_RSAPrivateKey_bio(bio, nil)
                }
            }
        }

        fileprivate init(keySize: _RSA.Signing.KeySize) throws {
            let pointer = CCryptoBoringSSL_RSA_new()!

            // This do block is used to avoid the risk of leaking the above pointer.
            do {
                let rc = RSA_F4.withBignumPointer { bignumPtr in
                    CCryptoBoringSSL_RSA_generate_key_ex(
                        pointer, CInt(keySize.bitCount), bignumPtr, nil
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
            return BIOHelper.withWritableMemoryBIO { bio in
                let rsaPrivateKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
                let rc = CCryptoBoringSSL_i2d_RSAPrivateKey_bio(bio, rsaPrivateKey)
                precondition(rc == 1)

                return try! Data(copyingMemoryBIO: bio)
            }
        }

        fileprivate var pemRepresentation: String {
            return BIOHelper.withWritableMemoryBIO { bio in
                let rsaPrivateKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
                let rc = CCryptoBoringSSL_PEM_write_bio_RSAPrivateKey(bio, rsaPrivateKey, nil, nil, 0, nil, nil)
                precondition(rc == 1)

                return try! String(copyingUTF8MemoryBIO: bio)
            }
        }

        fileprivate var pkcs8PEMRepresentation: String {
            return BIOHelper.withWritableMemoryBIO { bio in
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
            let rsaPublicKey = CCryptoBoringSSL_RSAPublicKey_dup(CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer))
            CCryptoBoringSSL_EVP_PKEY_assign_RSA(pkey, rsaPublicKey)
            let backing = BoringSSLRSAPublicKey.Backing(
                takingOwnershipOf: pkey
            )
            return BoringSSLRSAPublicKey(backing)
        }

        fileprivate func signature<D: Digest>(for digest: D, padding: _RSA.Signing.Padding) throws -> _RSA.Signing.RSASignature {
            let rsaPrivateKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
            let hashDigestType = try DigestType(forDigestType: D.self)
            let outputSize = Int(CCryptoBoringSSL_RSA_size(rsaPrivateKey))

            let output = try Array<UInt8>(unsafeUninitializedCapacity: outputSize) { bufferPtr, length in
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

        fileprivate func decrypt<D: DataProtocol>(_ data: D, padding: _RSA.Encryption.Padding) throws -> Data {
            let rsaPrivateKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
            let outputSize = Int(CCryptoBoringSSL_RSA_size(rsaPrivateKey))
            var output = Data(count: outputSize)

            let contiguousData: ContiguousBytes = data.regions.count == 1 ? data.regions.first! : Array(data)
            let writtenLength: CInt = try output.withUnsafeMutableBytes { bufferPtr in
                try contiguousData.withUnsafeBytes { dataPtr in
                    let ctx = CCryptoBoringSSL_EVP_PKEY_CTX_new(self.pointer, nil)
                    defer {
                        CCryptoBoringSSL_EVP_PKEY_CTX_free(ctx)
                    }

                    CCryptoBoringSSL_EVP_PKEY_decrypt_init(ctx)
                    switch padding.backing {
                    case let .pkcs1_oaep(digest):
                        CCryptoBoringSSL_EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING)
                        switch digest {
                        case .sha1:
                            break // default case, nothing to set
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

            output.removeSubrange(output.index(output.startIndex, offsetBy: Int(writtenLength)) ..< output.endIndex)
            return output
        }

        fileprivate func blindSignature<D: DataProtocol>(for message: D) throws -> _RSA.BlindSigning.BlindSignature {
            let rsaPrivateKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
            let signatureByteCount = Int(CCryptoBoringSSL_RSA_size(rsaPrivateKey))

            guard message.count == signatureByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            let messageBytes: ContiguousBytes = message.regions.count == 1 ? message.regions.first! : Array(message)

            let signatureBytes = try Array<UInt8>(unsafeUninitializedCapacity: signatureByteCount) { signatureBufferPtr, signatureBufferCount in
                try messageBytes.withUnsafeBytes { messageBufferPtr in
                    /// NOTE: BoringSSL promotes the use of `RSA_sign_raw` over `RSA_private_encrypt`.
                    var outputCount = 0
                    guard CCryptoBoringSSL_RSA_sign_raw(
                        rsaPrivateKey,
                        &outputCount,
                        signatureBufferPtr.baseAddress,
                        signatureBufferPtr.count,
                        messageBufferPtr.baseAddress,
                        messageBufferPtr.count,
                        RSA_NO_PADDING
                    ) == 1 else {
                        if ERR_GET_REASON(CCryptoBoringSSL_ERR_get_error()) == RSA_R_DATA_TOO_LARGE_FOR_MODULUS {
                            // "Message representative out of range" error in RFC9474.
                            throw CryptoKitError.incorrectParameterSize
                        }
                        throw CryptoKitError.internalBoringSSLError()
                    }
                    precondition(outputCount == signatureByteCount)
                    signatureBufferCount = outputCount
                }
            }
            let signature = _RSA.BlindSigning.BlindSignature(signatureBytes: signatureBytes)

            // NOTE: Verification is part of the specification.
            try self.verifyBlindSignature(signature, for: messageBytes)

            return _RSA.BlindSigning.BlindSignature(signatureBytes: signatureBytes)
        }

        fileprivate func verifyBlindSignature<D: ContiguousBytes>(_ signature: _RSA.BlindSigning.BlindSignature, for blindedMessage: D) throws {
            try signature.withUnsafeBytes { signatureBufferPtr in
                try blindedMessage.withUnsafeBytes { blindedMessageBufferPtr in
                    try withUnsafeTemporaryAllocation(byteCount: blindedMessageBufferPtr.count, alignment: 1) { verificationBufferPtr in
                        let rsaPublicKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
                        var outputCount = 0
                        /// NOTE: BoringSSL promotes the use of `RSA_verify_raw` over `RSA_public_decrypt`.
                        guard CCryptoBoringSSL_RSA_verify_raw(
                            rsaPublicKey,
                            &outputCount,
                            verificationBufferPtr.baseAddress,
                            verificationBufferPtr.count,
                            signatureBufferPtr.baseAddress,
                            signatureBufferPtr.count,
                            RSA_NO_PADDING
                        ) == 1 else {
                            throw CryptoKitError.internalBoringSSLError()
                        }
                        guard
                            outputCount == blindedMessageBufferPtr.count,
                            memcmp(verificationBufferPtr.baseAddress!, blindedMessageBufferPtr.baseAddress!, blindedMessageBufferPtr.count) == 0
                        else {
                            // "Signing failure" in RFC9474.
                            throw CryptoKitError.authenticationFailure
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
