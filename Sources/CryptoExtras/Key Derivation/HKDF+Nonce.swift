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
    public static func _deriveAESGCMNonce<Salt: DataProtocol, Info: DataProtocol>(
        inputKeyMaterial: SymmetricKey,
        salt: Salt,
        info: Info,
        sequenceNumber: UInt64 = 0
    ) throws -> AES.GCM.Nonce {
        var prefixedInfo = Data("SwiftCrypto.HKDF.AES-GCM-Nonce\0".utf8)
        var seq = sequenceNumber.bigEndian
        Swift.withUnsafeBytes(of: &seq) { prefixedInfo.append(contentsOf: $0) }
        prefixedInfo.append(contentsOf: info)

        let derived = deriveKey(
            inputKeyMaterial: inputKeyMaterial,
            salt: salt,
            info: prefixedInfo,
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
    ///   - sequenceNumber: A sequence number to guarantee unique nonces per message/record under the same key.
    /// - Returns: A derived `ChaChaPoly.Nonce`.
    /// - Throws: `CryptoKitError` if the derived bytes cannot form a valid nonce.
    public static func _deriveChaChaPolyNonce<Salt: DataProtocol, Info: DataProtocol>(
        inputKeyMaterial: SymmetricKey,
        salt: Salt,
        info: Info,
        sequenceNumber: UInt64 = 0
    ) throws -> ChaChaPoly.Nonce {
        var prefixedInfo = Data("SwiftCrypto.HKDF.ChaChaPoly-Nonce\0".utf8)
        var seq = sequenceNumber.bigEndian
        Swift.withUnsafeBytes(of: &seq) { prefixedInfo.append(contentsOf: $0) }
        prefixedInfo.append(contentsOf: info)

        let derived = deriveKey(
            inputKeyMaterial: inputKeyMaterial,
            salt: salt,
            info: prefixedInfo,
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
    ///   - sequenceNumber: A sequence number to guarantee unique nonces per message/record under the same key.
    /// - Returns: A derived `AES.GCM.Nonce`.
    /// - Throws: `CryptoKitError` if the derived bytes cannot form a valid nonce.
    public func _hkdfDerivedAESGCMNonce<H: HashFunction, Salt: DataProtocol, Info: DataProtocol>(
        using hashFunction: H.Type,
        salt: Salt,
        sharedInfo: Info,
        sequenceNumber: UInt64 = 0
    ) throws -> AES.GCM.Nonce {
        var prefixedInfo = Data("SwiftCrypto.HKDF.AES-GCM-Nonce\0".utf8)
        var seq = sequenceNumber.bigEndian
        Swift.withUnsafeBytes(of: &seq) { prefixedInfo.append(contentsOf: $0) }
        prefixedInfo.append(contentsOf: sharedInfo)

        let key = hkdfDerivedSymmetricKey(
            using: hashFunction,
            salt: salt,
            sharedInfo: prefixedInfo,
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
    ///   - sequenceNumber: A sequence number to guarantee unique nonces per message/record under the same key.
    /// - Returns: A derived `ChaChaPoly.Nonce`.
    /// - Throws: `CryptoKitError` if the derived bytes cannot form a valid nonce.
    public func _hkdfDerivedChaChaPolyNonce<H: HashFunction, Salt: DataProtocol, Info: DataProtocol>(
        using hashFunction: H.Type,
        salt: Salt,
        sharedInfo: Info,
        sequenceNumber: UInt64 = 0
    ) throws -> ChaChaPoly.Nonce {
        var prefixedInfo = Data("SwiftCrypto.HKDF.ChaChaPoly-Nonce\0".utf8)
        var seq = sequenceNumber.bigEndian
        Swift.withUnsafeBytes(of: &seq) { prefixedInfo.append(contentsOf: $0) }
        prefixedInfo.append(contentsOf: sharedInfo)

        let key = hkdfDerivedSymmetricKey(
            using: hashFunction,
            salt: salt,
            sharedInfo: prefixedInfo,
            outputByteCount: 12
        )
        return try key.withUnsafeBytes { try ChaChaPoly.Nonce(data: $0) }
    }
}
