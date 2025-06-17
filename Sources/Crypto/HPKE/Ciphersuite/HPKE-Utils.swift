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
#if os(Windows)
import ucrt
#elseif canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Android)
import Android
#elseif canImport(WASILibc)
import WASILibc
#endif
import FoundationEssentials
#else
import Foundation
#endif
#endif


@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
internal func I2OSP(value: Int, outputByteCount: Int) -> Data {
    precondition(outputByteCount > 0, "Cannot I2OSP with no output length.")
    precondition(value >= 0, "I2OSP requires a non-null value.")
    
    #if !CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    let requiredBytes = Int(ceil(log2(Double(max(value, 1) + 1)) / 8))
    #else
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    let requiredBytes = Int((log2_bridge(Double(max(value, 1) + 1)) / 8).rounded(.up))
    #endif
    
    precondition(outputByteCount >= requiredBytes)
    
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    var data = Data(repeating: 0, count: outputByteCount)
    
    for i in (outputByteCount - requiredBytes)...(outputByteCount - 1) {
        data[i] = UInt8(truncatingIfNeeded: (value >> (8 * (outputByteCount - 1 - i))))
    }
    
    return data
}

#endif // Linux or !SwiftPM
