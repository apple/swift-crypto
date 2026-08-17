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

@_implementationOnly import CCryptoBoringSSL
import Crypto

struct BoringSSLSHA512256HashFunction {
    static var digestSize: Int {
        Int(SHA256_DIGEST_LENGTH)
    }

    static func initialize() -> SHA512_CTX? {
        var context = SHA512_CTX()
        guard CCryptoBoringSSL_SHA512_256_Init(&context) == 1 else {
            return nil
        }
        return context
    }

    static func update(_ context: inout SHA512_CTX, data: UnsafeRawBufferPointer) -> Bool {
        let result = CCryptoBoringSSL_SHA512_256_Update(&context, data.baseAddress, data.count)
        return result == 1
    }

    static func finalize(_ context: inout SHA512_CTX, digest: UnsafeMutableRawBufferPointer) -> Bool {
        guard let baseAddress = digest.baseAddress, digest.count == Self.digestSize else {
            return false
        }
        let result = CCryptoBoringSSL_SHA512_256_Final(baseAddress, &context)
        return result == 1
    }
}
