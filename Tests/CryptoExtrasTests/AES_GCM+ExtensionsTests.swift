//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import CryptoExtras
import XCTest

final class AESGCMExtensionsTests: XCTestCase {
    func testSealOverOutputSpanAppendsCiphertext() throws {
        guard #available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *) else {
            throw XCTSkip("Array.span requires macOS 26.0+, iOS 26.0+, watchOS 26.0+, tvOS 26.0+, visionOS 26.0+")
        }
        let key = SymmetricKey(size: .bits256)
        let nonce = AES.GCM.Nonce()
        let plaintext = Array("Some Super Secret Message".utf8)
        let authenticatedData = Array("Some Authenticated Data".utf8)

        var ciphertext = [UInt8](repeating: 0xFF, count: 1 + plaintext.count)
        var tag = [UInt8](repeating: 0, count: 16)
        try ciphertext.withUnsafeMutableBytes { ciphertextBuffer in
            try tag.withUnsafeMutableBytes { tagBuffer in
                var ciphertextOutput = OutputRawSpan(buffer: ciphertextBuffer, initializedCount: 1)
                var tagOutput = OutputRawSpan(buffer: tagBuffer, initializedCount: 0)
                try AES.GCM._seal(
                    plaintext.span.bytes,
                    using: key,
                    nonce: nonce,
                    authenticating: authenticatedData.span.bytes,
                    tag: &tagOutput,
                    output: &ciphertextOutput
                )
                XCTAssertEqual(ciphertextOutput.byteCount, ciphertextBuffer.count)
                XCTAssertEqual(tagOutput.byteCount, tagBuffer.count)
            }
        }

        let sealedBox = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: authenticatedData)
        XCTAssertEqual(ciphertext, [0xFF] + Array(sealedBox.ciphertext))
        XCTAssertEqual(tag, Array(sealedBox.tag))
    }

    func testOpenOverOutputSpanAppendsPlaintext() throws {
        guard #available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *) else {
            throw XCTSkip("Array.span requires macOS 26.0+, iOS 26.0+, watchOS 26.0+, tvOS 26.0+, visionOS 26.0+")
        }
        let key = SymmetricKey(size: .bits256)
        let nonce = AES.GCM.Nonce()
        let plaintext = Array("Some Super Secret Message".utf8)
        let authenticatedData = Array("Some Authenticated Data".utf8)
        let sealedBox = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: authenticatedData)
        let ciphertext = Array(sealedBox.ciphertext)
        let tag = Array(sealedBox.tag)

        var decrypted = [UInt8](repeating: 0xFF, count: 1 + ciphertext.count)
        try decrypted.withUnsafeMutableBytes { decryptedBuffer in
            var output = OutputRawSpan(buffer: decryptedBuffer, initializedCount: 1)
            try AES.GCM._open(
                ciphertext.span.bytes,
                using: key,
                nonce: nonce,
                authenticating: authenticatedData.span.bytes,
                tag: tag.span.bytes,
                output: &output
            )
            XCTAssertEqual(output.byteCount, decryptedBuffer.count)
        }
        XCTAssertEqual(decrypted, [0xFF] + plaintext)
    }

    func testOpenOverOutputSpanWithModifiedTagThrows() throws {
        guard #available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *) else {
            throw XCTSkip("Array.span requires macOS 26.0+, iOS 26.0+, watchOS 26.0+, tvOS 26.0+, visionOS 26.0+")
        }
        let key = SymmetricKey(size: .bits256)
        let nonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(Array("Some Super Secret Message".utf8), using: key, nonce: nonce)
        let ciphertext = Array(sealedBox.ciphertext)
        var tag = Array(sealedBox.tag)
        tag[0] ^= 1

        var decrypted = [UInt8](repeating: 0, count: ciphertext.count)
        try decrypted.withUnsafeMutableBytes { decryptedBuffer in
            var output = OutputRawSpan(buffer: decryptedBuffer, initializedCount: 0)
            XCTAssertThrowsError(
                try AES.GCM._open(
                    ciphertext.span.bytes,
                    using: key,
                    nonce: nonce,
                    tag: tag.span.bytes,
                    output: &output
                )
            )
            XCTAssertEqual(output.byteCount, 0)
        }
    }
}
