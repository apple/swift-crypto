//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
#if CRYPTOKIT_STATIC_LIBRARY
@_exported import CryptoKit_Static
#else
@_exported import CryptoKit
#endif
#else

#if CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
import SwiftSystem
#else
import Foundation
#endif

extension HPKE {
    /// The key derivation functions to use in HPKE.
    public enum KDF: CaseIterable, Hashable {
		/// An HMAC-based key derivation function that uses SHA-2 hashing with a 256-bit digest.
        case HKDF_SHA256
		/// An HMAC-based key derivation function that uses SHA-2 hashing with a 384-bit digest.
        case HKDF_SHA384
		/// An HMAC-based key derivation function that uses SHA-2 hashing with a 512-bit digest.
        case HKDF_SHA512
        
        /// Return the KDF algorithm identifier as defined in section 7.2 of [RFC 9180](https://www.ietf.org/rfc/rfc9180.pdf).
        internal var value: UInt16 {
            switch self {
            case .HKDF_SHA256: return 0x0001
            case .HKDF_SHA384: return 0x0002
            case .HKDF_SHA512: return 0x0003
            }
        }
        
        internal var identifier: Data {
            return I2OSP(value: Int(self.value), outputByteCount: 2)
        }
        
        /// Hash Function Output Size
        internal var Nh: Int {
            switch self {
            case .HKDF_SHA256:
                return SHA256.Digest.byteCount
            case .HKDF_SHA384:
                return SHA384.Digest.byteCount
            case .HKDF_SHA512:
                return SHA512.Digest.byteCount
            }
        }
        
		/// Creates cryptographically strong key material from initial key material that you specify.
		///
		/// Generate a derived symmetric key from the cryptographically strong key material this function
		/// creates by calling ``expand(prk:info:outputByteCount:)``.
		///
		/// - Parameters:
		///  - salt: The salt to use for key derivation.
		///  - ikm: The initial key material the derivation function uses to derive a key.
		///
		/// - Returns: A pseudorandom, cryptographically strong key in the form of a hashed authentication code.
        func extract<S: DataProtocol>(salt: S, ikm: SymmetricKey) -> SymmetricKey {
            switch self {
            case .HKDF_SHA256:
                return SymmetricKey(data: HKDF<SHA256>.extract(inputKeyMaterial: ikm, salt: salt))
            case .HKDF_SHA384:
                return SymmetricKey(data: HKDF<SHA384>.extract(inputKeyMaterial: ikm, salt: salt))
            case .HKDF_SHA512:
                return SymmetricKey(data: HKDF<SHA512>.extract(inputKeyMaterial: ikm, salt: salt))
            }
        }
        
		/// Expands cryptographically strong key material into a derived symmetric key.
		///
		/// Generate cryptographically strong key material to use with this function by calling
		/// ``extract(salt:ikm:)``.
		///
		/// - Parameters:
		///  - prk: A pseudorandom, cryptographically strong key generated from the ``extract(salt:ikm:)`` function.
		///  - info: The shared information to use for key derivation.
		///  - outputByteCount: The length in bytes of the resulting symmetric key.
		///
		/// - Returns: The derived symmetric key.
        func expand(prk: SymmetricKey, info: Data, outputByteCount: Int) -> SymmetricKey {
            switch self {
            case .HKDF_SHA256:
                return SymmetricKey(data: HKDF<SHA256>.expand(pseudoRandomKey: prk, info: info, outputByteCount: outputByteCount))
            case .HKDF_SHA384:
                return SymmetricKey(data: HKDF<SHA384>.expand(pseudoRandomKey: prk, info: info, outputByteCount: outputByteCount))
            case .HKDF_SHA512:
                return SymmetricKey(data: HKDF<SHA512>.expand(pseudoRandomKey: prk, info: info, outputByteCount: outputByteCount))
            }
        }
    }
}

#endif // Linux or !SwiftPM
