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

#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// Nothing; this is implemented in RSA_security
#else
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

    internal func blindSignature<D: DataProtocol>(_ blindedMessage: D) throws -> _RSA.BlindSigning.BlindSignature {
        return try self.backing.blindSignature(blindedMessage)
    }
 }

extension BoringSSLRSAPublicKey {
    func isValidSignature<D: Digest>(_ signature: _RSA.Signing.RSASignature, for digest: D, padding: _RSA.Signing.Padding) -> Bool {
        return self.backing.isValidSignature(signature, for: digest, padding: padding)
    }
    
    internal func encrypt<D: DataProtocol>(_ data: D, padding: _RSA.Encryption.Padding) throws -> Data {
        return try self.backing.encrypt(data, padding: padding)
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

        fileprivate func blindSignature<D: DataProtocol>(_ blindedMessage: D) throws -> _RSA.BlindSigning.BlindSignature {
            let rsaPrivateKey = CCryptoBoringSSL_EVP_PKEY_get0_RSA(self.pointer)
            let signatureByteCount = Int(CCryptoBoringSSL_RSA_size(rsaPrivateKey))

            guard blindedMessage.count == signatureByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            let blindedMessageBytes: ContiguousBytes = blindedMessage.regions.count == 1 ? blindedMessage.regions.first! : Array(blindedMessage)

            let signatureBytes = try Array<UInt8>(unsafeUninitializedCapacity: signatureByteCount) { signatureBufferPtr, signatureBufferCount in
                try blindedMessageBytes.withUnsafeBytes { blindedMessageBufferPtr in
                    /// NOTE: BoringSSL promotes the use of `RSA_sign_raw` over `RSA_private_encrypt`.
                    var outputCount = 0
                    guard CCryptoBoringSSL_RSA_sign_raw(
                        rsaPrivateKey,
                        &outputCount,
                        signatureBufferPtr.baseAddress,
                        signatureBufferPtr.count,
                        blindedMessageBufferPtr.baseAddress,
                        blindedMessageBufferPtr.count,
                        RSA_NO_PADDING
                    ) == 1 else {
                        throw CryptoKitError.internalBoringSSLError()
                    }
                    precondition(outputCount == signatureByteCount)
                    signatureBufferCount = outputCount
                }
            }
            let signature = _RSA.BlindSigning.BlindSignature(signatureBytes: signatureBytes)

            // NOTE: Verification is part of the specification.
            try self.verifyBlindSignature(signature, for: blindedMessageBytes)

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
#endif
