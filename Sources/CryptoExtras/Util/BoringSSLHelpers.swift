//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// NOTE: This file is unconditionally compiled because RSABSSA is implemented using BoringSSL on all platforms.
@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
internal enum BIOHelper {
    static func withReadOnlyMemoryBIO<ReturnValue>(
        wrapping pointer: UnsafeRawBufferPointer, _ block: (OpaquePointer) throws -> ReturnValue
    ) rethrows -> ReturnValue {
        let bio = CCryptoBoringSSL_BIO_new_mem_buf(pointer.baseAddress, pointer.count)!
        defer {
            CCryptoBoringSSL_BIO_free(bio)
        }

        return try block(bio)
    }

    static func withReadOnlyMemoryBIO<ReturnValue>(
        wrapping pointer: UnsafeBufferPointer<UInt8>, _ block: (OpaquePointer) throws -> ReturnValue
    ) rethrows -> ReturnValue {
        let bio = CCryptoBoringSSL_BIO_new_mem_buf(pointer.baseAddress, pointer.count)!
        defer {
            CCryptoBoringSSL_BIO_free(bio)
        }

        return try block(bio)
    }

    static func withWritableMemoryBIO<ReturnValue>(_ block: (OpaquePointer) throws -> ReturnValue) rethrows -> ReturnValue {
        let bio = CCryptoBoringSSL_BIO_new(CCryptoBoringSSL_BIO_s_mem())!
        defer {
            CCryptoBoringSSL_BIO_free(bio)
        }

        return try block(bio)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Data {
    init(copyingMemoryBIO bio: OpaquePointer) throws {
        var innerPointer: UnsafePointer<UInt8>? = nil
        var innerLength = 0

        guard 1 == CCryptoBoringSSL_BIO_mem_contents(bio, &innerPointer, &innerLength) else {
            throw CryptoKitError.internalBoringSSLError()
        }

        self = Data(UnsafeBufferPointer(start: innerPointer, count: innerLength))
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension String {
    init(copyingUTF8MemoryBIO bio: OpaquePointer) throws {
        var innerPointer: UnsafePointer<UInt8>? = nil
        var innerLength = 0

        guard 1 == CCryptoBoringSSL_BIO_mem_contents(bio, &innerPointer, &innerLength) else {
            throw CryptoKitError.internalBoringSSLError()
        }

        self = String(decoding: UnsafeBufferPointer(start: innerPointer, count: innerLength), as: UTF8.self)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
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
