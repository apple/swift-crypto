//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else

// For temporary purposes we pretend that ArraySlice is our "bigint" type. We don't really need anything else.
extension ArraySlice: ASN1Serializable where Element == UInt8 { }

extension ArraySlice: ASN1Parseable where Element == UInt8 { }

extension ArraySlice: ASN1IntegerRepresentable where Element == UInt8 {
    // We only use unsigned "bigint"s
    static var isSigned: Bool {
        return false
    }

    init(asn1IntegerBytes: ArraySlice<UInt8>) throws {
        self = asn1IntegerBytes
    }

    func withBigEndianIntegerBytes<ReturnType>(_ body: (ArraySlice<UInt8>) throws -> ReturnType) rethrows -> ReturnType {
        return try body(self)
    }
}
#endif
