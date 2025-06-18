//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2021-2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import Crypto

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

#if !canImport(CommonCrypto)
@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
internal struct BoringSSLPBKDF2 {
    /// Derives a secure key using the provided hash function, passphrase and salt.
    ///
    /// - Parameters:
    ///    - password: The passphrase, which should be used as a basis for the key. This can be any type that conforms to `DataProtocol`, like `Data` or an array of `UInt8` instances.
    ///    - salt: The salt to use for key derivation.
    ///    - outputByteCount: The length in bytes of resulting symmetric key.
    ///    - rounds: The number of rounds which should be used to perform key derivation.
    /// - Returns: The derived symmetric key.
    static func deriveKey<Passphrase: DataProtocol, Salt: DataProtocol>(
        from password: Passphrase,
        salt: Salt,
        using hashFunction: KDF.Insecure.PBKDF2.HashFunction,
        outputByteCount: Int,
        rounds: Int
    ) throws -> SymmetricKey {
        // This should be SecureBytes, but we can't use that here.
        var derivedKeyData = Data(count: outputByteCount)

        let rc = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes -> Int32 in
            let saltBytes: ContiguousBytes = salt.regions.count == 1 ? salt.regions.first! : Array(salt)
            return saltBytes.withUnsafeBytes { saltBytes -> Int32 in
                let passwordBytes: ContiguousBytes =
                    password.regions.count == 1 ? password.regions.first! : Array(password)
                return passwordBytes.withUnsafeBytes { passwordBytes -> Int32 in
                    CCryptoBoringSSL_PKCS5_PBKDF2_HMAC(
                        passwordBytes.baseAddress!,
                        passwordBytes.count,
                        saltBytes.baseAddress!,
                        saltBytes.count,
                        UInt32(rounds),
                        hashFunction.digest,
                        derivedKeyBytes.count,
                        derivedKeyBytes.baseAddress!
                    )
                }
            }
        }

        guard rc == 1 else {
            throw CryptoKitError.internalBoringSSLError()
        }

        return SymmetricKey(data: derivedKeyData)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension KDF.Insecure.PBKDF2.HashFunction {
    var digest: OpaquePointer {
        switch self {
        case .insecureMD5:
            return CCryptoBoringSSL_EVP_md5()
        case .insecureSHA1:
            return CCryptoBoringSSL_EVP_sha1()
        case .insecureSHA224:
            return CCryptoBoringSSL_EVP_sha224()
        case .sha256:
            return CCryptoBoringSSL_EVP_sha256()
        case .sha384:
            return CCryptoBoringSSL_EVP_sha384()
        case .sha512:
            return CCryptoBoringSSL_EVP_sha512()
        default:
            preconditionFailure("Unsupported hash function: \(self.rawValue)")
        }
    }
}

#endif
