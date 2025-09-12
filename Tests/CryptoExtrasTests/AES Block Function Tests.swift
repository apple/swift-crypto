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
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import XCTest
import Crypto
import CryptoExtras

final class AESBlockFunctionTests: XCTestCase {
    static let nistPlaintextChunks: [[UInt8]] = [
        try! Array(hexString: "6bc1bee22e409f96e93d7e117393172a"),
        try! Array(hexString: "ae2d8a571e03ac9c9eb76fac45af8e51"),
        try! Array(hexString: "30c81c46a35ce411e5fbc1191a0a52ef"),
        try! Array(hexString: "f69f2445df4f9b17ad2b417be66c3710")
    ]

    func test128BitEncrypt() throws {
        let key = SymmetricKey(
            data: try! Array(hexString: "2b7e151628aed2a6abf7158809cf4f3c")
        )

        let encryptedChunks = [
            try! Array(hexString: "3ad77bb40d7a3660a89ecaf32466ef97"),
            try! Array(hexString: "f5d3d58503b9699de785895a96fdbaaf"),
            try! Array(hexString: "43b1cd7f598ece23881b00e3ed030688"),
            try! Array(hexString: "7b0c785e27e8ad3f8223207104725dd4")
        ]

        // Fast-path
        for (chunk, expected) in zip(Self.nistPlaintextChunks, encryptedChunks) {
            var chunk = chunk
            try AES.permute(&chunk, key: key)
            XCTAssertEqual(chunk, expected)
        }

        // Slow-path
        for (chunk, expected) in zip(Self.nistPlaintextChunks, encryptedChunks) {
            var block = Block(wrapped: chunk)
            try AES.permute(&block, key: key)
            XCTAssertEqual(Array(block.wrapped), expected)
        }
    }

    func test128BitDecrypt() throws {
        let key = SymmetricKey(
            data: try! Array(hexString: "2b7e151628aed2a6abf7158809cf4f3c")
        )

        let encryptedChunks = [
            try! Array(hexString: "3ad77bb40d7a3660a89ecaf32466ef97"),
            try! Array(hexString: "f5d3d58503b9699de785895a96fdbaaf"),
            try! Array(hexString: "43b1cd7f598ece23881b00e3ed030688"),
            try! Array(hexString: "7b0c785e27e8ad3f8223207104725dd4")
        ]

        // Fast-path
        for (chunk, expected) in zip(encryptedChunks, Self.nistPlaintextChunks) {
            var chunk = chunk
            try AES.inversePermute(&chunk, key: key)
            XCTAssertEqual(chunk, expected)
        }

        // Slow-path
        for (chunk, expected) in zip(encryptedChunks, Self.nistPlaintextChunks) {
            var block = Block(wrapped: chunk)
            try AES.inversePermute(&block, key: key)
            XCTAssertEqual(Array(block.wrapped), expected)
        }
    }

    func test192BitEncrypt() throws {
        let key = SymmetricKey(
            data: try! Array(hexString: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
        )

        let encryptedChunks = [
            try! Array(hexString: "bd334f1d6e45f25ff712a214571fa5cc"),
            try! Array(hexString: "974104846d0ad3ad7734ecb3ecee4eef"),
            try! Array(hexString: "ef7afd2270e2e60adce0ba2face6444e"),
            try! Array(hexString: "9a4b41ba738d6c72fb16691603c18e0e")
        ]

        // Fast-path
        for (chunk, expected) in zip(Self.nistPlaintextChunks, encryptedChunks) {
            var chunk = chunk
            try AES.permute(&chunk, key: key)
            XCTAssertEqual(chunk, expected)
        }

        // Slow-path
        for (chunk, expected) in zip(Self.nistPlaintextChunks, encryptedChunks) {
            var block = Block(wrapped: chunk)
            try AES.permute(&block, key: key)
            XCTAssertEqual(Array(block.wrapped), expected)
        }
    }

    func test192BitDecrypt() throws {
        let key = SymmetricKey(
            data: try! Array(hexString: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
        )

        let encryptedChunks = [
            try! Array(hexString: "bd334f1d6e45f25ff712a214571fa5cc"),
            try! Array(hexString: "974104846d0ad3ad7734ecb3ecee4eef"),
            try! Array(hexString: "ef7afd2270e2e60adce0ba2face6444e"),
            try! Array(hexString: "9a4b41ba738d6c72fb16691603c18e0e")
        ]

        // Fast-path
        for (chunk, expected) in zip(encryptedChunks, Self.nistPlaintextChunks) {
            var chunk = chunk
            try AES.inversePermute(&chunk, key: key)
            XCTAssertEqual(chunk, expected)
        }

        // Slow-path
        for (chunk, expected) in zip(encryptedChunks, Self.nistPlaintextChunks) {
            var block = Block(wrapped: chunk)
            try AES.inversePermute(&block, key: key)
            XCTAssertEqual(Array(block.wrapped), expected)
        }
    }

    func test256BitEncrypt() throws {
        let key = SymmetricKey(
            data: try! Array(
                hexString: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
            )
        )

        let encryptedChunks = [
            try! Array(hexString: "f3eed1bdb5d2a03c064b5a7e3db181f8"),
            try! Array(hexString: "591ccb10d410ed26dc5ba74a31362870"),
            try! Array(hexString: "b6ed21b99ca6f4f9f153e7b1beafed1d"),
            try! Array(hexString: "23304b7a39f9f3ff067d8d8f9e24ecc7")
        ]

        // Fast-path
        for (chunk, expected) in zip(Self.nistPlaintextChunks, encryptedChunks) {
            var chunk = chunk
            try AES.permute(&chunk, key: key)
            XCTAssertEqual(chunk, expected)
        }

        // Slow-path
        for (chunk, expected) in zip(Self.nistPlaintextChunks, encryptedChunks) {
            var block = Block(wrapped: chunk)
            try AES.permute(&block, key: key)
            XCTAssertEqual(Array(block.wrapped), expected)
        }
    }

    func test256BitDecrypt() throws {
        let key = SymmetricKey(
            data: try! Array(
                hexString: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
            )
        )

        let encryptedChunks = [
            try! Array(hexString: "f3eed1bdb5d2a03c064b5a7e3db181f8"),
            try! Array(hexString: "591ccb10d410ed26dc5ba74a31362870"),
            try! Array(hexString: "b6ed21b99ca6f4f9f153e7b1beafed1d"),
            try! Array(hexString: "23304b7a39f9f3ff067d8d8f9e24ecc7")
        ]

        // Fast-path
        for (chunk, expected) in zip(encryptedChunks, Self.nistPlaintextChunks) {
            var chunk = chunk
            try AES.inversePermute(&chunk, key: key)
            XCTAssertEqual(chunk, expected)
        }

        // Slow-path
        for (chunk, expected) in zip(encryptedChunks, Self.nistPlaintextChunks) {
            var block = Block(wrapped: chunk)
            try AES.inversePermute(&block, key: key)
            XCTAssertEqual(Array(block.wrapped), expected)
        }
    }

    func testRejectInvalidBlockSizes() throws {
        let key = SymmetricKey(size: .bits128)

        for blockSize in 0..<32 {
            if blockSize == 16 { continue }

            var chunk = Array(repeating: UInt8(0), count: blockSize)

            // Fast-path
            XCTAssertThrowsError(try AES.permute(&chunk, key: key))
            XCTAssertThrowsError(try AES.inversePermute(&chunk, key: key))

            // Slow-path
            var block = Block(wrapped: chunk)
            XCTAssertThrowsError(try AES.permute(&block, key: key))
            XCTAssertThrowsError(try AES.inversePermute(&block, key: key))
        }
    }

    func testRejectsInvalidKeySizes() throws {
        var chunk = Array(repeating: UInt8(0), count: 16)

        for keySizeInBits in stride(from: 128, through: 256, by: 8) {
            if [128, 192, 256].contains(keySizeInBits) { continue }

            let key = SymmetricKey(size: .init(bitCount: keySizeInBits))

            // Fast-path
            XCTAssertThrowsError(try AES.permute(&chunk, key: key))
            XCTAssertThrowsError(try AES.inversePermute(&chunk, key: key))

            // Slow-path
            var block = Block(wrapped: chunk)
            XCTAssertThrowsError(try AES.permute(&block, key: key))
            XCTAssertThrowsError(try AES.inversePermute(&block, key: key))
        }
    }
}

// We use this for testing. Specifically, there's a slow path in the code
// which ArraySlice and Data will not hit (for Collections that don't implement
// withContiguousMutableStorageIfAvailable). This is a simple Collection that wraps
// an ArraySlice but does not expose that method, so hits the slow path.
struct Block: MutableCollection {
    var wrapped: ArraySlice<UInt8>

    init(wrapped: ArraySlice<UInt8>) {
        self.wrapped = wrapped
    }

    init(wrapped: [UInt8]) {
        self.wrapped = wrapped[...]
    }

    var startIndex: Int { wrapped.startIndex }

    var endIndex: Int { wrapped.endIndex }

    func index(after index: Int) -> Int {
        return index + 1
    }

    subscript(position: Int) -> UInt8 {
        get {
            self.wrapped[position]
        }
        set {
            self.wrapped[position] = newValue
        }
    }
}
