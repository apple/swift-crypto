//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims
@_implementationOnly import CryptoBoringWrapper
import Foundation

extension AES {
    private static let blockSize = 128 / 8

    /// Apply the AES permutation operation in the encryption direction.
    ///
    /// This function applies the core AES block operation to `payload` in the encryption direction. Note that this is
    /// not performing any kind of block cipher mode, and does not authenticate the payload. This is a dangerous primitive
    /// that should only be used to compose higher-level primitives, and should not be used directly.
    ///
    /// - parameter payload: The payload to encrypt. Must be exactly 16 bytes long.
    /// - parameter key: The encryption key to use.
    /// - throws: On invalid parameter sizes.
    public static func permute<Payload: MutableCollection>(_ payload: inout Payload, key: SymmetricKey) throws where Payload.Element == UInt8 {
        return try Self.permuteBlock(&payload, key: key, permutation: .forward)
    }

    /// Apply the AES permutation operation in the decryption direction.
    ///
    /// This function applies the core AES block operation to `payload` in the decryption direction. Note that this is
    /// not performing any kind of block cipher mode, and does not authenticate the payload. This is a dangerous primitive
    /// that should only be used to compose higher-level primitives, and should not be used directly.
    ///
    /// - parameter payload: The payload to decrypt. Must be exactly 16 bytes long.
    /// - parameter key: The decryption key to use.
    /// - throws: On invalid parameter sizes.
    public static func inversePermute<Payload: MutableCollection>(_ payload: inout Payload, key: SymmetricKey) throws where Payload.Element == UInt8 {
        return try Self.permuteBlock(&payload, key: key, permutation: .backward)
    }

    private static func permuteBlock<Payload: MutableCollection>(_ payload: inout Payload, key: SymmetricKey, permutation: Permutation) throws where Payload.Element == UInt8 {
        if payload.count != Int(Self.blockSize) {
            throw CryptoKitError.incorrectParameterSize
        }

        if !AES.isValidKey(key) {
            throw CryptoKitError.incorrectKeySize
        }

        let requiresSlowPath: Bool = try payload.withContiguousMutableStorageIfAvailable { storage in
            try Self.permute(UnsafeMutableRawBufferPointer(storage), key: key, permutation: permutation)
            return false
        } ?? true

        if requiresSlowPath {
            try AES.Block.withStackStorage { blockBytes in
                precondition(blockBytes.count == payload.count)

                blockBytes.copyBytes(from: payload)
                try Self.permute(blockBytes, key: key, permutation: permutation)

                var index = payload.startIndex
                for byte in blockBytes {
                    payload[index] = byte
                    payload.formIndex(after: &index)
                }
            }
        }
    }

    enum Permutation {
        case forward
        case backward
    }

    private static func permute(_ payload: UnsafeMutableRawBufferPointer, key: SymmetricKey, permutation: Permutation) throws {
        precondition(AES.isValidKey(key))
        precondition(payload.count == Int(Self.blockSize))

        key.withUnsafeBytes { keyPtr in
            // We bind both pointers here. These binds are not technically safe, but because we
            // know the pointers don't persist they can't violate the aliasing rules. We really
            // want a "with memory rebound" function but we don't have it yet.
            let keyBytes = keyPtr.bindMemory(to: UInt8.self)
            let blockBytes = payload.bindMemory(to: UInt8.self)

            var key = AES_KEY()

            if permutation == .forward {
                let rc = CCryptoBoringSSL_AES_set_encrypt_key(keyBytes.baseAddress, UInt32(keyBytes.count * 8), &key)
                precondition(rc == 0)

                CCryptoBoringSSL_AES_encrypt(blockBytes.baseAddress, blockBytes.baseAddress, &key)
            } else {
                let rc = CCryptoBoringSSL_AES_set_decrypt_key(keyBytes.baseAddress, UInt32(keyBytes.count * 8), &key)
                precondition(rc == 0)

                CCryptoBoringSSL_AES_decrypt(blockBytes.baseAddress, blockBytes.baseAddress, &key)
            }
        }
    }

    private struct Block {
        private var storage: (UInt64, UInt64)

        private init() {
            assert(MemoryLayout<Self>.size == Int(AES.blockSize))
            self.storage = (0, 0)
        }

        private mutating func withUnsafeMutableBytes<ReturnType>(
            _ body: (UnsafeMutableRawBufferPointer) throws -> ReturnType
        ) rethrows -> ReturnType {
            return try Swift.withUnsafeMutableBytes(of: &self.storage, body)
        }

        static func withStackStorage<ReturnType>(
            _ body: (UnsafeMutableRawBufferPointer) throws -> ReturnType
        ) rethrows -> ReturnType {
            var storage = Self()
            return try storage.withUnsafeMutableBytes(body)
        }
    }

    private static func isValidKey(_ key: SymmetricKey) -> Bool {
        switch key.bitCount {
        case 128, 192, 256:
            return true
        default:
            return false
        }
    }
}

