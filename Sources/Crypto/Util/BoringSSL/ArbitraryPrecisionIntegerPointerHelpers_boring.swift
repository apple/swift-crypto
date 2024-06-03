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
@_implementationOnly import CCryptoBoringSSL
import CryptoBoringWrapper

extension ArbitraryPrecisionInteger {
    func withUnsafeBignumPointer<T>(_ body: (UnsafePointer<BIGNUM>) throws -> T) rethrows -> T {
        try self.withUnsafeRawBignumPointer { pointer in
            try body(pointer.assumingMemoryBound(to: BIGNUM.self))
        }
    }

    mutating func withUnsafeMutableBignumPointer<T>(_ body: (UnsafeMutablePointer<BIGNUM>) throws -> T) rethrows -> T {
        try self.withUnsafeMutableRawBignumPointer { pointer in
            try body(pointer.assumingMemoryBound(to: BIGNUM.self))
        }
    }
}
