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

#if !canImport(Security)
@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims

internal struct BoringSSLRSAPublicKey {
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


internal struct BoringSSLRSAPrivateKey {
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
 }

extension BoringSSLRSAPublicKey {
    func isValidSignature<D: Digest>(_ signature: _RSA.Signing.RSASignature, for digest: D, padding: _RSA.Signing.Padding) -> Bool {
        return self.backing.isValidSignature(signature, for: digest, padding: padding)
    }
}

extension BoringSSLRSAPublicKey {
    fileprivate final class Backing {
        private let pointer: UnsafeMutablePointer<RSA>

        fileprivate init(takingOwnershipOf pointer: UnsafeMutablePointer<RSA>) {
            self.pointer = pointer
        }

        fileprivate init(copying other: Backing) {
            self.pointer = CCryptoBoringSSL_RSAPublicKey_dup(other.pointer)
        }

        fileprivate init(pemRepresentation: String) throws {
            var pemRepresentation = pemRepresentation

            // There are two encodings for RSA public keys: PKCS#1 and the SPKI form.
            // The SPKI form is what we support for EC keys, so we try that first, then we
            // fall back to the PKCS#1 form if that parse fails.
            do {
                self.pointer = try pemRepresentation.withUTF8 { utf8Ptr in
                    return try BIOHelper.withReadOnlyMemoryBIO(wrapping: utf8Ptr) { bio in
                        guard let key = CCryptoBoringSSL_PEM_read_bio_RSA_PUBKEY(bio, nil, nil, nil) else {
                            throw CryptoKitError.internalBoringSSLError()
                        }
                        return key
                    }
                }
            } catch {
                self.pointer = try pemRepresentation.withUTF8 { utf8Ptr in
                    return try BIOHelper.withReadOnlyMemoryBIO(wrapping: utf8Ptr) { bio in
                        guard let key = CCryptoBoringSSL_PEM_read_bio_RSAPublicKey(bio, nil, nil, nil) else {
                            throw CryptoKitError.internalBoringSSLError()
                        }
                        return key
                    }
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
            // There are two encodings for RSA public keys: PKCS#1 and the SPKI form.
            // The SPKI form is what we support for EC keys, so we try that first, then we
            // fall back to the PKCS#1 form if that parse fails.
            do {
                self.pointer = try contiguousDerRepresentation.withUnsafeBytes { derPtr in
                    return try BIOHelper.withReadOnlyMemoryBIO(wrapping: derPtr) { bio in
                        guard let key = CCryptoBoringSSL_d2i_RSA_PUBKEY_bio(bio, nil) else {
                            throw CryptoKitError.internalBoringSSLError()
                        }
                        return key
                    }
                }
            } catch {
                self.pointer = try contiguousDerRepresentation.withUnsafeBytes { derPtr in
                    return try BIOHelper.withReadOnlyMemoryBIO(wrapping: derPtr) { bio in
                        guard let key = CCryptoBoringSSL_d2i_RSAPublicKey_bio(bio, nil) else {
                            throw CryptoKitError.internalBoringSSLError()
                        }
                        return key
                    }
                }
            }
        }

        fileprivate var pkcs1DERRepresentation: Data {
            return BIOHelper.withWritableMemoryBIO { bio in
                let rc = CCryptoBoringSSL_i2d_RSAPublicKey_bio(bio, self.pointer)
                precondition(rc == 1)

                return try! Data(copyingMemoryBIO: bio)
            }
        }

        fileprivate var pkcs1PEMRepresentation: String {
            return ASN1.PEMDocument(type: _RSA.PKCS1PublicKeyType, derBytes: self.pkcs1DERRepresentation).pemString
        }

        fileprivate var derRepresentation: Data {
            return BIOHelper.withWritableMemoryBIO { bio in
                let rc = CCryptoBoringSSL_i2d_RSA_PUBKEY_bio(bio, self.pointer)
                precondition(rc == 1)

                return try! Data(copyingMemoryBIO: bio)
            }
        }

        fileprivate var pemRepresentation: String {
            return ASN1.PEMDocument(type: _RSA.SPKIPublicKeyType, derBytes: self.derRepresentation).pemString
        }

        fileprivate var keySizeInBits: Int {
            return Int(CCryptoBoringSSL_RSA_size(self.pointer)) * 8
        }

        fileprivate func isValidSignature<D: Digest>(_ signature: _RSA.Signing.RSASignature, for digest: D, padding: _RSA.Signing.Padding) -> Bool {
            let hashDigestType = try! DigestType(forDigestType: D.self)

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
                            self.pointer
                        )
                    case .pss:
                        return CCryptoBoringSSLShims_RSA_verify_pss_mgf1(
                            self.pointer,
                            digestPtr.baseAddress,
                            digestPtr.count,
                            hashDigestType.dispatchTable,
                            hashDigestType.dispatchTable,
                            CInt(hashDigestType.digestLength),
                            signaturePtr.baseAddress,
                            signaturePtr.count
                        )
                    }
                }
                return rc == 1
            }
        }

        deinit {
            CCryptoBoringSSL_RSA_free(self.pointer)
        }
    }
}

extension BoringSSLRSAPrivateKey {
    fileprivate final class Backing {
        private let pointer: UnsafeMutablePointer<RSA>

        fileprivate init(copying other: Backing) {
            self.pointer = CCryptoBoringSSL_RSAPrivateKey_dup(other.pointer)
        }

        fileprivate init(pemRepresentation: String) throws {
            var pemRepresentation = pemRepresentation

            self.pointer = try pemRepresentation.withUTF8 { utf8Ptr in
                return try BIOHelper.withReadOnlyMemoryBIO(wrapping: utf8Ptr) { bio in
                    guard let key = CCryptoBoringSSL_PEM_read_bio_RSAPrivateKey(bio, nil, nil, nil) else {
                        throw CryptoKitError.internalBoringSSLError()
                    }

                    return key
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
            if let pointer = Backing.pkcs8DERPrivateKey(contiguousDerRepresentation) {
                self.pointer = pointer
            } else if let pointer = Backing.pkcs1DERPrivateKey(contiguousDerRepresentation) {
                self.pointer = pointer
            } else {
                throw CryptoKitError.internalBoringSSLError()
            }
        }

        private static func pkcs8DERPrivateKey<Bytes: ContiguousBytes>(_ derRepresentation: Bytes) -> UnsafeMutablePointer<RSA>? {
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

        private static func pkcs1DERPrivateKey<Bytes: ContiguousBytes>(_ derRepresentation: Bytes) -> UnsafeMutablePointer<RSA>? {
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

                self.pointer = pointer
            } catch {
                CCryptoBoringSSL_RSA_free(pointer)
                throw error
            }
        }

        fileprivate var derRepresentation: Data {
            return BIOHelper.withWritableMemoryBIO { bio in
                let rc = CCryptoBoringSSL_i2d_RSAPrivateKey_bio(bio, self.pointer)
                precondition(rc == 1)

                return try! Data(copyingMemoryBIO: bio)
            }
        }

        fileprivate var pemRepresentation: String {
            return BIOHelper.withWritableMemoryBIO { bio in
                let rc = CCryptoBoringSSL_PEM_write_bio_RSAPrivateKey(bio, self.pointer, nil, nil, 0, nil, nil)
                precondition(rc == 1)

                return try! String(copyingUTF8MemoryBIO: bio)
            }
        }

        fileprivate var keySizeInBits: Int {
            return Int(CCryptoBoringSSL_RSA_size(self.pointer)) * 8
        }

        fileprivate var publicKey: BoringSSLRSAPublicKey {
            let backing = BoringSSLRSAPublicKey.Backing(
                takingOwnershipOf: CCryptoBoringSSL_RSAPublicKey_dup(self.pointer)
            )
            return BoringSSLRSAPublicKey(backing)
        }

        fileprivate func signature<D: Digest>(for digest: D, padding: _RSA.Signing.Padding) throws -> _RSA.Signing.RSASignature {
            let hashDigestType = try DigestType(forDigestType: D.self)
            let outputSize = Int(CCryptoBoringSSL_RSA_size(self.pointer))

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
                            self.pointer
                        )
                        outputLength = Int(writtenLength)
                        return rc
                    case .pss:
                        return CCryptoBoringSSLShims_RSA_sign_pss_mgf1(
                            self.pointer,
                            &outputLength,
                            bufferPtr.baseAddress,
                            bufferPtr.count,
                            digestPtr.baseAddress,
                            digestPtr.count,
                            hashDigestType.dispatchTable,
                            hashDigestType.dispatchTable,
                            CInt(hashDigestType.digestLength)
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

        deinit {
            CCryptoBoringSSL_RSA_free(self.pointer)
        }
    }
}
#endif
