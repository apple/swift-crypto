//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import Foundation

extension AES {
    public enum _CTR {
        private static func encryptInPlace(
            _ plaintext: UnsafeMutableRawBufferPointer,
            using key: SymmetricKey,
            nonce: AES._CTR.Nonce
        ) throws {
            precondition(MemoryLayout<AES._CTR.Nonce>.size == 16)

            guard [128, 192, 256].contains(key.bitCount) else {
                throw CryptoKitError.incorrectKeySize
            }

            var nonce = nonce

            for offset in stride(from: 0, to: plaintext.count, by: MemoryLayout<AES._CTR.Nonce>.size) {
                var nonceCopy = nonce

                try nonceCopy.withUnsafeMutableBytes { noncePtr in
                    var noncePtr = noncePtr
                    try AES.permute(&noncePtr, key: key)
                    let remainingPlaintextBytes = plaintext.count &- offset

                    for i in 0..<min(remainingPlaintextBytes, MemoryLayout<AES._CTR.Nonce>.size) {
                        plaintext[offset &+ i] ^= noncePtr[i]
                    }
                }

                nonce.incrementCounter()
            }
        }

        public static func encrypt<Plaintext: DataProtocol>(
            _ plaintext: Plaintext,
            using key: SymmetricKey,
            nonce: AES._CTR.Nonce
        ) throws -> Data {
            var flattenedPlaintext = Data(plaintext)
            try flattenedPlaintext.withUnsafeMutableBytes {
                try Self.encryptInPlace($0, using: key, nonce: nonce)
            }
            return flattenedPlaintext
        }

        private static func decryptInPlace(
            _ ciphertext: UnsafeMutableRawBufferPointer,
            using key: SymmetricKey,
            nonce: AES._CTR.Nonce
        ) throws {
            // Surprise, CTR mode is symmetric in encryption/decryption!
            try Self.encryptInPlace(ciphertext, using: key, nonce: nonce)
        }

        public static func decrypt<Ciphertext: DataProtocol>(
            _ ciphertext: Ciphertext,
            using key: SymmetricKey,
            nonce: AES._CTR.Nonce
        ) throws -> Data {
            var flattenedCiphertext = Data(ciphertext)
            try flattenedCiphertext.withUnsafeMutableBytes {
                try Self.decryptInPlace($0, using: key, nonce: nonce)
            }
            return flattenedCiphertext
        }
    }
}

extension AES._CTR {
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

        mutating func incrementCounter() {
            var (newValue, overflow) = UInt32(bigEndian: self.nonceBytes.2).addingReportingOverflow(1)
            self.nonceBytes.2 = newValue.bigEndian

            if overflow {
                (newValue, overflow) = UInt32(bigEndian: self.nonceBytes.1).addingReportingOverflow(1)
                self.nonceBytes.1 = newValue.bigEndian
            }

            if overflow {
                // If this overflows that's fine: we'll have overflowed everything and gone back to 0.
                self.nonceBytes.0 = (UInt64(bigEndian: self.nonceBytes.0) &+ 1).bigEndian
            }
        }

        mutating func withUnsafeMutableBytes<ReturnType>(_ body: (UnsafeMutableRawBufferPointer) throws -> ReturnType) rethrows -> ReturnType {
            return try Swift.withUnsafeMutableBytes(of: &self.nonceBytes, body)
        }
    }
}
