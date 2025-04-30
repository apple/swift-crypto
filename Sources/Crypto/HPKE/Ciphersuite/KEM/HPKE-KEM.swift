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
import Foundation

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension HPKE {
	/// The key encapsulation mechanisms to use in HPKE.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum KEM: CaseIterable, Hashable {
		/// A key encapsulation mechanism using NIST P-256 elliptic curve key agreement
		/// and SHA-2 hashing with a 256-bit digest.
        case P256_HKDF_SHA256
		/// A key encapsulation mechanism using NIST P-384 elliptic curve key agreement
		/// and SHA-2 hashing with a 384-bit digest.
        case P384_HKDF_SHA384
		/// A key encapsulation mechanism using NIST P-521 elliptic curve key agreement
		/// and SHA-2 hashing with a 512-bit digest.
        case P521_HKDF_SHA512
		/// A key encapsulation mechanism using X25519 elliptic curve key agreement
		/// and SHA-2 hashing with a 256-bit digest.
        case Curve25519_HKDF_SHA256
        
        internal var value: UInt16 {
            switch self {
            case .P256_HKDF_SHA256:         return 0x0010
            case .P384_HKDF_SHA384:         return 0x0011
            case .P521_HKDF_SHA512:         return 0x0012
            case .Curve25519_HKDF_SHA256:   return 0x0020
            }
        }
        
        internal var kdf: HPKE.KDF {
            switch self {
            case .P256_HKDF_SHA256:         return .HKDF_SHA256
            case .P384_HKDF_SHA384:         return .HKDF_SHA384
            case .P521_HKDF_SHA512:         return .HKDF_SHA512
            case .Curve25519_HKDF_SHA256:   return .HKDF_SHA256
            }
        }
        
        internal var identifier: Data {
            return I2OSP(value: Int(self.value), outputByteCount: 2)
        }
        
        internal var nSecret: UInt16 {
            switch self {
            case .P256_HKDF_SHA256:         return 32
            case .P384_HKDF_SHA384:         return 48
            case .P521_HKDF_SHA512:         return 64
            case .Curve25519_HKDF_SHA256:   return 32
            }
        }
    }
}

#endif // Linux or !SwiftPM
