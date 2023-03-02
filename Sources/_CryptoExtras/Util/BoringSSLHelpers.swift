//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if !canImport(Security)
@_implementationOnly import CCryptoBoringSSL
import Foundation
import Crypto

internal enum BIOHelper {
    static func withReadOnlyMemoryBIO<ReturnValue>(
        wrapping pointer: UnsafeRawBufferPointer, _ block: (UnsafeMutablePointer<BIO>) throws -> ReturnValue
    ) rethrows -> ReturnValue {
        let bio = CCryptoBoringSSL_BIO_new_mem_buf(pointer.baseAddress, pointer.count)!
        defer {
            CCryptoBoringSSL_BIO_free(bio)
        }

        return try block(bio)
    }

    static func withReadOnlyMemoryBIO<ReturnValue>(
        wrapping pointer: UnsafeBufferPointer<UInt8>, _ block: (UnsafeMutablePointer<BIO>) throws -> ReturnValue
    ) rethrows -> ReturnValue {
        let bio = CCryptoBoringSSL_BIO_new_mem_buf(pointer.baseAddress, pointer.count)!
        defer {
            CCryptoBoringSSL_BIO_free(bio)
        }

        return try block(bio)
    }

    static func withWritableMemoryBIO<ReturnValue>(_ block: (UnsafeMutablePointer<BIO>) throws -> ReturnValue) rethrows -> ReturnValue {
        let bio = CCryptoBoringSSL_BIO_new(CCryptoBoringSSL_BIO_s_mem())!
        defer {
            CCryptoBoringSSL_BIO_free(bio)
        }

        return try block(bio)
    }
}

extension Data {
    init(copyingMemoryBIO bio: UnsafeMutablePointer<BIO>) throws {
        var innerPointer: UnsafePointer<UInt8>? = nil
        var innerLength = 0

        guard 1 == CCryptoBoringSSL_BIO_mem_contents(bio, &innerPointer, &innerLength) else {
            throw CryptoKitError.internalBoringSSLError()
        }

        self = Data(UnsafeBufferPointer(start: innerPointer, count: innerLength))
    }
}

extension String {
    init(copyingUTF8MemoryBIO bio: UnsafeMutablePointer<BIO>) throws {
        var innerPointer: UnsafePointer<UInt8>? = nil
        var innerLength = 0

        guard 1 == CCryptoBoringSSL_BIO_mem_contents(bio, &innerPointer, &innerLength) else {
            throw CryptoKitError.internalBoringSSLError()
        }

        self = String(decoding: UnsafeBufferPointer(start: innerPointer, count: innerLength), as: UTF8.self)
    }
}

extension FixedWidthInteger {
    func withBignumPointer<ReturnType>(_ block: (UnsafeMutablePointer<BIGNUM>) throws -> ReturnType) rethrows -> ReturnType {
        precondition(self.bitWidth <= UInt.bitWidth)

        var bn = BIGNUM()
        CCryptoBoringSSL_BN_init(&bn)
        defer {
            CCryptoBoringSSL_BN_clear(&bn)
        }

        CCryptoBoringSSL_BN_set_word(&bn, .init(self))

        return try block(&bn)
    }
}
#endif
