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
typealias AESCFBImpl = OpenSSLAESCFBImpl

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AES {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum _CFB {
        @inlinable
        public static func encrypt<Plaintext: DataProtocol>(
            _ plaintext: Plaintext,
            using key: SymmetricKey,
            iv: AES._CFB.IV
        ) throws -> Data {
            let bytes: ContiguousBytes = plaintext.regions.count == 1 ? plaintext.regions.first! : Array(plaintext)
            return try AESCFBImpl.encryptOrDecrypt(.encrypt, bytes, using: key, iv: iv)
        }

        @inlinable
        public static func decrypt<Ciphertext: DataProtocol>(
            _ ciphertext: Ciphertext,
            using key: SymmetricKey,
            iv: AES._CFB.IV
        ) throws -> Data {
            let bytes: ContiguousBytes = ciphertext.regions.count == 1 ? ciphertext.regions.first! : Array(ciphertext)
            return try AESCFBImpl.encryptOrDecrypt(.decrypt, bytes, using: key, iv: iv)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AES._CFB {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public struct IV: Sendable {
        // AES CFB uses a 128-bit IV.
        private var ivBytes: (UInt64, UInt64)

        public init() {
            var rng = SystemRandomNumberGenerator()
            self.ivBytes = (rng.next(), rng.next())
        }

        public init<IVBytes: Collection>(ivBytes: IVBytes) throws where IVBytes.Element == UInt8 {
            guard ivBytes.count == 16 else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.ivBytes = (0, 0)

            Swift.withUnsafeMutableBytes(of: &self.ivBytes) { bytesPtr in
                bytesPtr.copyBytes(from: ivBytes)
            }
        }

        mutating func withUnsafeMutableBytes<ReturnType>(_ body: (UnsafeMutableRawBufferPointer) throws -> ReturnType) rethrows -> ReturnType {
            return try Swift.withUnsafeMutableBytes(of: &self.ivBytes, body)
        }
    }
}
