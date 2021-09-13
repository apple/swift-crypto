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

#if canImport(CommonCrypto)
@_implementationOnly import CommonCrypto

internal struct CommonCryptoPBKDF2<H: HashFunction> {
    /// Derives a secure key using the provided hash function, passphrase and salt.
    ///
    /// - Parameters:
    ///    - password: The passphrase, which should be used as a basis for the key. This can be any type that conforms to `DataProtocol`, like `Data` or an array of `UInt8` instances.
    ///    - salt: The salt to use for key derivation.
    ///    - outputByteCount: The length in bytes of resulting symmetric key.
    ///    - rounds: The number of rounds which should be used to perform key derivation.
    /// - Returns: The derived symmetric key.
    public static func deriveKey<Passphrase: DataProtocol, Salt: DataProtocol>(from password: Passphrase, salt: Salt, outputByteCount: Int, rounds: Int) throws -> SymmetricKey {
        // MARK: This code should never be called, as every known `HashFunction` should also conform to `CommonCryptoHashFunction`
        throw CryptoKitError.incorrectParameterSize
    }
}

extension CommonCryptoPBKDF2 where H: CommonCryptoHashFunction {
    /// Derives a secure key using the provided hash function, passphrase and salt.
    ///
    /// - Parameters:
    ///    - password: The passphrase, which should be used as a basis for the key. This can be any type that conforms to `DataProtocol`, like `Data` or an array of `UInt8` instances.
    ///    - salt: The salt to use for key derivation.
    ///    - outputByteCount: The length in bytes of resulting symmetric key.
    ///    - rounds: The number of rounds which should be used to perform key derivation.
    /// - Returns: The derived symmetric key.
    public static func deriveKey<Passphrase: DataProtocol, Salt: DataProtocol>(from password: Passphrase, salt: Salt, outputByteCount: Int, rounds: Int) throws -> SymmetricKey {
        var derivedKeyData = Data(count: outputByteCount)
        let derivedCount = derivedKeyData.count
        let derivationStatus = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes -> Int32 in
            let keyBuffer: UnsafeMutablePointer<UInt8> =
            derivedKeyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
            let saltBytes: ContiguousBytes = salt.regions.count == 1 ? salt.regions.first! : Array(salt)
            return saltBytes.withUnsafeBytes { saltBytes -> Int32 in
                let saltBuffer = saltBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
                let passwordBytes: ContiguousBytes = password.regions.count == 1 ? password.regions.first! : Array(password)
                return passwordBytes.withUnsafeBytes { passwordBytes -> Int32 in
                    let passwordBuffer = passwordBytes.baseAddress!.assumingMemoryBound(to: Int8.self)
                    return CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                                passwordBuffer,
                                                password.count,
                                                saltBuffer,
                                                salt.count,
                                                CCPBKDFAlgorithm(H.digestHmacType),
                                                UInt32(rounds),
                                                keyBuffer,
                                                derivedCount)
                }
            }
        }
        if derivationStatus != kCCSuccess {
            throw CryptoKitError.underlyingCoreCryptoError(error: derivationStatus)
        }
        return SymmetricKey(data: derivedKeyData)
    }
}

// MARK: - CommonCryptoHashFunction

protocol CommonCryptoHashFunction: HashFunction {
    static var digestHmacType: Int { get }
}

extension Insecure.MD5: CommonCryptoHashFunction {
    static var digestHmacType: Int {
        kCCHmacAlgMD5
    }
}

extension Insecure.SHA1: CommonCryptoHashFunction {
    static var digestHmacType: Int {
        kCCPRFHmacAlgSHA1
    }
}

extension SHA256: CommonCryptoHashFunction {
    static var digestHmacType: Int {
        kCCPRFHmacAlgSHA256
    }
}

extension SHA384: CommonCryptoHashFunction {
    static var digestHmacType: Int {
        kCCPRFHmacAlgSHA384
    }
}

extension SHA512: CommonCryptoHashFunction {
    static var digestHmacType: Int {
        kCCPRFHmacAlgSHA512
    }
}

#endif
