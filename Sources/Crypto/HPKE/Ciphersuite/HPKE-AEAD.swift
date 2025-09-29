//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else

#if CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
import SwiftSystem
#else
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
#endif


@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension HPKE {
    /// The authenticated encryption with associated data (AEAD) algorithms to use in HPKE.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum AEAD: CaseIterable, Hashable, Sendable {
		/// An Advanced Encryption Standard cipher in Galois/Counter Mode with a key length of 128 bits.
        case AES_GCM_128
		/// An Advanced Encryption Standard cipher in Galois/Counter Mode with a key length of 256 bits.
        case AES_GCM_256
		/// A ChaCha20 stream cipher with the Poly1305 message authentication code.
        case chaChaPoly
		/// An export-only mode.
		///
		/// In export-only mode, HPKE negotiates key derivation, but you can't use it to encrypt or decrypt data.
        case exportOnly
        
        /// Return the AEAD algorithm identifier as defined in section 7.3 of [RFC 9180](https://www.ietf.org/rfc/rfc9180.pdf).
        @_spi(HPKEAlgID)
        public var value: UInt16 {
            switch self {
            case .AES_GCM_128: return 0x0001
            case .AES_GCM_256: return 0x0002
            case .chaChaPoly:  return 0x0003
            case .exportOnly: return 0xFFFF
            }
        }
        
        var isExportOnly: Bool {
            return self == .exportOnly
        }
        
        /// Return the AEAD key size in bytes
        @_spi(HPKEAlgID)
        public var keyByteCount: Int {
            switch self {
            case .AES_GCM_128:
                return 16
            case .AES_GCM_256:
                return 32
            case .chaChaPoly:
                return 32
            case .exportOnly:
                fatalError("ExportOnly should not return a key size.")
            }
        }
        
        /// Return the AEAD nonce size in bytes
        @_spi(HPKEAlgID)
        public var nonceByteCount: Int {
            switch self {
            case .AES_GCM_128, .AES_GCM_256, .chaChaPoly:
                return 12
            case .exportOnly:
                fatalError("ExportOnly should not return a nonce size.")
            }
        }
        
        /// Return the AEAD tag size in bytes
        @_spi(HPKEAlgID)
        public var tagByteCount: Int {
            switch self {
            case .AES_GCM_128, .AES_GCM_256, .chaChaPoly:
                return 16
            case .exportOnly:
                fatalError("ExportOnly should not return a tag size.")
            }
        }
        
        internal var identifier: Data {
            return I2OSP(value: Int(self.value), outputByteCount: 2)
        }
        
        @_spi(MLS)
        public func seal<D: DataProtocol, AD: DataProtocol>(_ message: D, authenticating aad: AD, nonce: Data, using key: SymmetricKey) throws -> Data {
            switch self {
            case .chaChaPoly:
                return try ChaChaPoly.seal(message, using: key, nonce: ChaChaPoly.Nonce(data: nonce), authenticating: aad).combined.dropFirst(nonce.count)
            default:
                return try AES.GCM.seal(message, using: key, nonce: AES.GCM.Nonce(data: nonce), authenticating: aad).combined!.dropFirst(nonce.count)
            }
        }
        
        @_spi(MLS)
        public func open<C: DataProtocol, AD: DataProtocol>(_ ct: C, nonce: Data, authenticating aad: AD, using key: SymmetricKey) throws -> Data {
            guard ct.count >= self.tagByteCount else {
                throw HPKE.Errors.expectedPSK
            }
            
            switch self {
            case .AES_GCM_128, .AES_GCM_256: do {
                let nonce = try AES.GCM.Nonce(data: nonce)
                let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ct.dropLast(16), tag: ct.suffix(16))
                return try AES.GCM.open(sealedBox, using: key, authenticating: aad)
            }
            case .chaChaPoly: do {
                let nonce = try ChaChaPoly.Nonce(data: nonce)
                let sealedBox = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ct.dropLast(16), tag: ct.suffix(16))
                return try ChaChaPoly.open(sealedBox, using: key, authenticating: aad)
            }
            case .exportOnly:
                throw HPKE.Errors.exportOnlyMode
            }
        }
    }
}

#endif // Linux or !SwiftPM
