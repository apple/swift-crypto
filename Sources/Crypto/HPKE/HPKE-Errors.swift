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
    /// Hybrid public key encryption (HPKE) errors that CryptoKit uses.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum Errors: Error {
		/// The parameters for initializing an HPKE sender or receiver are inconsistent.
        case inconsistentParameters
		/// The supplied encryption key is incompatible with the requested cipher suite.
        case inconsistentCiphersuiteAndKey
		/// The object is in export-only mode and received a request to encrypt or decrypt data.
        case exportOnlyMode
		/// The PSK is nil and the PSK ID isn't nil, or the PSK ID is nil and the PSK isn't nil.
        case inconsistentPSKInputs
		/// The PSK is nil and the object is in PSK mode, or in authentication and PSK mode.
        case expectedPSK
		/// The PSK isn't nil and the object is in base mode, or in authentication mode.
        case unexpectedPSK
		/// The sequence number for encrypting or decrypting the message is out of range.
        case outOfRangeSequenceNumber
		/// The ciphertext is too short.
        case ciphertextTooShort
    }
}

#endif // Linux or !SwiftPM
