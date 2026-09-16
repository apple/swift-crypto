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

#if canImport(CryptoKit)
@_exported import CryptoKit
#else
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension HPKE {
	/// The key encapsulation mechanisms to use in HPKE.
    ///
    /// The module-lattice key encapsulation mechanism (ML-KEM) is designed to offer increased security in situations
    /// where an adversary uses a quantum computer.
    @nonexhaustive
    public enum KEM: CaseIterable, Hashable, Sendable {
        public static var allCases: [HPKE.KEM] {
            var cases = [KEM.P256_HKDF_SHA256, KEM.P384_HKDF_SHA384, KEM.P521_HKDF_SHA512, KEM.Curve25519_HKDF_SHA256]
            if #available(iOS 19.0, macOS 16.0, watchOS 12.0, tvOS 19.0, macCatalyst 19.0, *) {
                cases.append(KEM.XWingMLKEM768X25519)
            }
            return cases
        }

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
        /// A key encapsulation mechanism using the X-Wing (ML-KEM-768 with X25519) key encapsulation mechanism
        /// and SHA-2 hashing with a 256-bit digest.
        case XWingMLKEM768X25519

        /// Return the KEM algorithm identifier as defined in section 7.1 of [RFC 9180](https://www.ietf.org/rfc/rfc9180.pdf).
        internal var value: UInt16 {
            switch self {
            case .P256_HKDF_SHA256:          return 0x0010
            case .P384_HKDF_SHA384:          return 0x0011
            case .P521_HKDF_SHA512:          return 0x0012
            case .Curve25519_HKDF_SHA256:    return 0x0020
            case .XWingMLKEM768X25519: return 0x647a // https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-06#name-iana-considerations
            }
        }
        
        internal var kdf: HPKE.KDF {
            switch self {
            case .P256_HKDF_SHA256:          return .HKDF_SHA256
            case .P384_HKDF_SHA384:          return .HKDF_SHA384
            case .P521_HKDF_SHA512:          return .HKDF_SHA512
            case .Curve25519_HKDF_SHA256:    return .HKDF_SHA256
            case .XWingMLKEM768X25519:       return .HKDF_SHA256
            }
        }
        
        internal var identifier: Data {
            return I2OSP(value: Int(self.value), outputByteCount: 2)
        }
        
        internal var nSecret: UInt16 {
            switch self {
            case .P256_HKDF_SHA256:          return 32
            case .P384_HKDF_SHA384:          return 48
            case .P521_HKDF_SHA512:          return 64
            case .Curve25519_HKDF_SHA256:    return 32
            case .XWingMLKEM768X25519:       return 32
            }
        }
        
        /// Return the size of the encapsulation in bytes
        internal var nEnc: UInt16 {
            switch self {
            case .P256_HKDF_SHA256:          return 65
            case .P384_HKDF_SHA384:          return 97
            case .P521_HKDF_SHA512:          return 133
            case .Curve25519_HKDF_SHA256:    return 32
            case .XWingMLKEM768X25519:       return 1120
            }
        }
    }
}

#endif // canImport(CryptoKit)
