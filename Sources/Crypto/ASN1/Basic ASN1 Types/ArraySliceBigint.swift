//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else

#if CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
import SwiftSystem
#else
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
#endif

// For temporary purposes we pretend that ArraySlice is our "bigint" type. We don't really need anything else.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArraySlice: ASN1Serializable where Element == UInt8 { }

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArraySlice: ASN1Parseable where Element == UInt8 { }

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArraySlice: ASN1ImplicitlyTaggable where Element == UInt8 { }

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ArraySlice: ASN1IntegerRepresentable where Element == UInt8 {
    // We only use unsigned "bigint"s
    static var isSigned: Bool {
        return false
    }

    init(asn1IntegerBytes: ArraySlice<UInt8>) throws(CryptoKitMetaError) {
        self = asn1IntegerBytes
    }

    func withBigEndianIntegerBytes<ReturnType>(_ body: (ArraySlice<UInt8>) throws(CryptoKitMetaError) -> ReturnType) throws(CryptoKitMetaError) -> ReturnType {
        return try body(self)
    }
}

#endif // Linux or !SwiftPM
