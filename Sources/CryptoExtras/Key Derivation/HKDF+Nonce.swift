//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
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

@available(macOS 11.0, iOS 14.0, watchOS 7.0, tvOS 14.0, *)
extension HKDF {
    /// Derives an AES-GCM nonce from key material using HKDF key derivation.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: The main symmetric key used as input key material.
    ///   - salt: The salt to use for key derivation.
    ///   - info: The shared information to use for key derivation.
    /// - Returns: A derived `AES.GCM.Nonce`.
    /// - Throws: `CryptoKitError` if the derived bytes cannot form a valid nonce.
    public static func deriveAESGCMNonce<Salt: DataProtocol, Info: DataProtocol>(
        inputKeyMaterial: SymmetricKey,
        salt: Salt,
        info: Info
    ) throws -> AES.GCM.Nonce {
        let derived = deriveKey(
            inputKeyMaterial: inputKeyMaterial,
            salt: salt,
            info: info,
            outputByteCount: 12
        )
        return try derived.withUnsafeBytes { try AES.GCM.Nonce(data: $0) }
    }

    /// Derives a ChaChaPoly nonce from key material using HKDF key derivation.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: The main symmetric key used as input key material.
    ///   - salt: The salt to use for key derivation.
    ///   - info: The shared information to use for key derivation.
    /// - Returns: A derived `ChaChaPoly.Nonce`.
    /// - Throws: `CryptoKitError` if the derived bytes cannot form a valid nonce.
    public static func deriveChaChaPolyNonce<Salt: DataProtocol, Info: DataProtocol>(
        inputKeyMaterial: SymmetricKey,
        salt: Salt,
        info: Info
    ) throws -> ChaChaPoly.Nonce {
        let derived = deriveKey(
            inputKeyMaterial: inputKeyMaterial,
            salt: salt,
            info: info,
            outputByteCount: 12
        )
        return try derived.withUnsafeBytes { try ChaChaPoly.Nonce(data: $0) }
    }
}

@available(macOS 11.0, iOS 14.0, watchOS 7.0, tvOS 14.0, *)
extension SharedSecret {
    /// Derives an AES-GCM nonce from the shared secret using HKDF.
    ///
    /// - Parameters:
    ///   - hashFunction: The hash function to use for HKDF derivation.
    ///   - salt: The salt to use for key derivation.
    ///   - sharedInfo: The shared context information to use for key derivation.
    /// - Returns: A derived `AES.GCM.Nonce`.
    /// - Throws: `CryptoKitError` if the derived bytes cannot form a valid nonce.
    public func hkdfDerivedAESGCMNonce<H: HashFunction, Salt: DataProtocol, Info: DataProtocol>(
        using hashFunction: H.Type,
        salt: Salt,
        sharedInfo: Info
    ) throws -> AES.GCM.Nonce {
        let key = hkdfDerivedSymmetricKey(
            using: hashFunction,
            salt: salt,
            sharedInfo: sharedInfo,
            outputByteCount: 12
        )
        return try key.withUnsafeBytes { try AES.GCM.Nonce(data: $0) }
    }

    /// Derives a ChaChaPoly nonce from the shared secret using HKDF.
    ///
    /// - Parameters:
    ///   - hashFunction: The hash function to use for HKDF derivation.
    ///   - salt: The salt to use for key derivation.
    ///   - sharedInfo: The shared context information to use for key derivation.
    /// - Returns: A derived `ChaChaPoly.Nonce`.
    /// - Throws: `CryptoKitError` if the derived bytes cannot form a valid nonce.
    public func hkdfDerivedChaChaPolyNonce<H: HashFunction, Salt: DataProtocol, Info: DataProtocol>(
        using hashFunction: H.Type,
        salt: Salt,
        sharedInfo: Info
    ) throws -> ChaChaPoly.Nonce {
        let key = hkdfDerivedSymmetricKey(
            using: hashFunction,
            salt: salt,
            sharedInfo: sharedInfo,
            outputByteCount: 12
        )
        return try key.withUnsafeBytes { try ChaChaPoly.Nonce(data: $0) }
    }
}
