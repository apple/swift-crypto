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

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias AESCTRImpl = OpenSSLAESCTRImpl

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AES {

    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum _CTR {
        @inlinable
        public static func encrypt<Plaintext: DataProtocol>(
            _ plaintext: Plaintext,
            using key: SymmetricKey,
            nonce: AES._CTR.Nonce
        ) throws -> Data {
            let bytes: ContiguousBytes = plaintext.regions.count == 1 ? plaintext.regions.first! : Array(plaintext)
            return try AESCTRImpl.encrypt(bytes, using: key, nonce: nonce)
        }

        @inlinable
        public static func decrypt<Ciphertext: DataProtocol>(
            _ ciphertext: Ciphertext,
            using key: SymmetricKey,
            nonce: AES._CTR.Nonce
        ) throws -> Data {
            // Surprise, CTR mode is symmetric in encryption/decryption!
            try Self.encrypt(ciphertext, using: key, nonce: nonce)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AES._CTR {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public struct Nonce: Sendable {
        // AES CTR uses a 128-bit counter. It's most usual to use a 96-bit nonce
        // and a 32-bit counter at the end, so we support that specific mode of
        // operation here.
        private var nonceBytes: (
            UInt64, UInt32, UInt32
        )

        public init() {
            var rng = SystemRandomNumberGenerator()
            self.nonceBytes = (
                rng.next(), rng.next(), rng.next()
            )
        }

        public init<NonceBytes: Collection>(nonceBytes: NonceBytes) throws where NonceBytes.Element == UInt8 {
            // We support a 96-bit nonce (with a 32-bit counter, initialized to 0) or a full 128-bit
            // expression.
            guard nonceBytes.count == 12 || nonceBytes.count == 16 else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.nonceBytes = (
                0, 0, 0
            )

            Swift.withUnsafeMutableBytes(of: &self.nonceBytes) { bytesPtr in
                bytesPtr.copyBytes(from: nonceBytes)
            }
        }

        mutating func withUnsafeMutableBytes<ReturnType>(_ body: (UnsafeMutableRawBufferPointer) throws -> ReturnType) rethrows -> ReturnType {
            return try Swift.withUnsafeMutableBytes(of: &self.nonceBytes, body)
        }
    }
}
