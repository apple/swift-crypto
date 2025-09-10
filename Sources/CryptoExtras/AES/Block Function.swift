//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims
import CryptoBoringWrapper
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
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
            var block = AES.Block()
            try block.withUnsafeMutableBytes { blockBytes in
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

    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
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

    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    struct Block {
        private static var blockSize: Int { 16 }

        typealias BlockBytes = (
            UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
            UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8
        )

        // 128-bit block size
        private var blockBytes: BlockBytes

        fileprivate init() {
            self.blockBytes = (
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0
            )
        }

        init(_ blockBytes: BlockBytes) {
            self.blockBytes = blockBytes
        }

        init(_ iv: AES._CBC.IV) {
            self.blockBytes = iv.ivBytes
        }

        init<BlockBytes: Collection>(blockBytes: BlockBytes) where BlockBytes.Element == UInt8 {
            // The block size is always 16. Pad out past there.
            precondition(blockBytes.count <= Self.blockSize)

            self.blockBytes = (
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0
            )

            Swift.withUnsafeMutableBytes(of: &self.blockBytes) { bytesPtr in
                bytesPtr.copyBytes(from: blockBytes)

                // Early exit here.
                if blockBytes.count == Self.blockSize {
                    return
                }

                var remainingBytes = bytesPtr.dropFirst(blockBytes.count)
                let padByte = UInt8(remainingBytes.count)

                for index in remainingBytes.indices {
                    remainingBytes[index] = padByte
                }
            }
        }

        static var paddingBlock: Block {
            // The padding block is a full block of value blocksize.
            let value = UInt8(truncatingIfNeeded: Self.blockSize)
            return Block((
                value, value, value, value, value, value, value, value,
                value, value, value, value, value, value, value, value
            ))
        }

        func withUnsafeBytes<ReturnType>(_ body: (UnsafeRawBufferPointer) throws -> ReturnType) rethrows -> ReturnType {
            return try Swift.withUnsafeBytes(of: self.blockBytes, body)
        }

        mutating func withUnsafeMutableBytes<ReturnType>(_ body: (UnsafeMutableRawBufferPointer) throws -> ReturnType) rethrows -> ReturnType {
            return try Swift.withUnsafeMutableBytes(of: &self.blockBytes, body)
        }

        static func ^= (lhs: inout Block, rhs: Block) {
            // Ideally we'd not use raw pointers for this.
            lhs.withUnsafeMutableBytes { lhsPtr in
                rhs.withUnsafeBytes { rhsPtr in
                    assert(lhsPtr.count == Self.blockSize)
                    assert(rhsPtr.count == Self.blockSize)

                    for index in 0..<Self.blockSize {
                        lhsPtr[index] ^= rhsPtr[index]
                    }
                }
            }
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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AES.Block: RandomAccessCollection, MutableCollection {
    var startIndex: Int {
        0
    }

    var endIndex: Int {
        Self.blockSize
    }

    subscript(position: Int) -> UInt8 {
        get {
            precondition(position >= 0)
            precondition(position < Self.blockSize)

            return self.withUnsafeBytes { $0[position] }
        }

        set {
            precondition(position >= 0)
            precondition(position < Self.blockSize)

            self.withUnsafeMutableBytes { $0[position] = newValue }
        }
    }

    func withContiguousStorageIfAvailable<ReturnValue>(
        _ body: (UnsafeBufferPointer<UInt8>) throws -> ReturnValue)
    rethrows -> ReturnValue? {
        return try withUnsafePointer(to: self.blockBytes) { tuplePtr in
            // Homogeneous tuples are always bound to the element type as well as to their own type.
            let retyped = UnsafeRawPointer(tuplePtr).assumingMemoryBound(to: UInt8.self)
            let bufferised = UnsafeBufferPointer(start: retyped, count: Self.blockSize)
            return try body(bufferised)
        }
    }

    mutating func withContiguousMutableStorageIfAvailable<ReturnValue>(
        _ body: (inout UnsafeMutableBufferPointer<UInt8>) throws -> ReturnValue)
    rethrows -> ReturnValue? {
        return try withUnsafeMutablePointer(to: &self.blockBytes) { tuplePtr in
            // Homogeneous tuples are always bound to the element type as well as to their own type.
            let retyped = UnsafeMutableRawPointer(tuplePtr).assumingMemoryBound(to: UInt8.self)
            var bufferised = UnsafeMutableBufferPointer(start: retyped, count: Self.blockSize)
            return try body(&bufferised)
        }
    }
}
