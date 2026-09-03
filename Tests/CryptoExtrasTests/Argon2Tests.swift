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

import XCTest
import Crypto
import CryptoExtras

final class Argon2Tests: XCTestCase {
    /// Verified against official RFC 9106 test vectors.
    /// See: https://www.rfc-editor.org/rfc/rfc9106.html#section-5.3
    func testRFC9106Argon2idTestVector() throws {
        // From RFC 9106, Section 5.3
        let password = Data(repeating: 0x01, count: 32)
        let salt = Data(repeating: 0x02, count: 16)
        let secret = Data(repeating: 0x03, count: 8)
        let ad = Data(repeating: 0x04, count: 12)
        
        // Settings: Argon2id, v=13, m=32, t=3, p=4
        let key = try KDF.Argon2id.deriveKey(
            from: password,
            salt: salt,
            outputByteCount: 32,
            iterations: 3,
            memoryByteCount: 32 * 1024, // 32 KiB
            parallelism: 4,
            secret: secret,
            associatedData: ad
        )
        
        let expectedHash = Data([
            0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 
            0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9, 
            0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 
            0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59
        ])
        
        key.withUnsafeBytes {
            XCTAssertEqual(Data($0), expectedHash, "Hash should match RFC 9106 test vector (Section 5.3)")
        }
    }
}
