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

#if !canImport(CommonCrypto)
@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims

internal struct BoringSSLPBKDF2<H: HashFunction> {
    /// Derives a secure key using the provided hash function, passphrase and salt.
    ///
    /// - Parameters:
    ///    - password: The passphrase, which should be used as a basis for the key. This can be any type that conforms to `DataProtocol`, like `Data` or an array of `UInt8` instances.
    ///    - salt: The salt to use for key derivation.
    ///    - outputByteCount: The length in bytes of resulting symmetric key.
    ///    - rounds: The number of rounds which should be used to perform key derivation.
    /// - Returns: The derived symmetric key.
    public static func deriveKey<Passphrase: DataProtocol, Salt: DataProtocol>(from password: Passphrase, salt: Salt, outputByteCount: Int, rounds: Int) throws -> SymmetricKey {
        let digest: OpaquePointer
        if H.self == Insecure.MD5.self {
            digest = CCryptoBoringSSL_EVP_md5()
        } else if H.self == Insecure.SHA1.self {
            digest = CCryptoBoringSSL_EVP_sha1()
        } else if H.self == SHA256.self {
            digest = CCryptoBoringSSL_EVP_sha256()
        } else if H.self == SHA384.self {
            digest = CCryptoBoringSSL_EVP_sha384()
        } else if H.self == SHA512.self {
            digest = CCryptoBoringSSL_EVP_sha512()
        } else {
            // TODO: Use a better error
            throw CryptoKitError.incorrectParameterSize
        }

        var derivedKeyData = SecureBytes(count: outputByteCount)
        let derivedCount = derivedKeyData.count
        let rc = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes -> Int32 in
            let keyBuffer: UnsafeMutablePointer<UInt8> =
                derivedKeyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
            let saltBytes: ContiguousBytes = salt.regions.count == 1 ? salt.regions.first! : Array(salt)
            return saltBytes.withUnsafeBytes { saltBytes -> Int32 in
                let saltBuffer = saltBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
                let passwordBytes: ContiguousBytes = password.regions.count == 1 ? password.regions.first! : Array(password)
                return passwordBytes.withUnsafeBytes { passwordBytes -> Int32 in
                    let passwordBuffer = passwordBytes.baseAddress!.assumingMemoryBound(to: Int8.self)
                    return CCryptoBoringSSL_PKCS5_PBKDF2_HMAC(passwordBuffer, password.count,
                                                       saltBuffer, salt.count,
                                                       UInt32(rounds), digest,
                                                       derivedCount, keyBuffer)
                }
            }
        }
        guard rc == 1 else {
            throw CryptoKitError.internalBoringSSLError()
        }

        return SymmetricKey(data: derivedKeyData)
    }
}

#endif
