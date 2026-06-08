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
#elseif CRYPTOKIT_NO_IMPORT_FOUNDATION
#else
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
#endif

extension Data {
    /// Copy the raw bytes from the given span into a new Data instance.
    init(copying bytes: RawSpan) {
        if bytes.byteCount == 0 {
            self = Data()
        } else {
            self = bytes.withUnsafeBytes { buffer in
                Data(
                    UnsafeBufferPointer<UInt8>(
                        start: buffer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        count: buffer.count
                    )
                )
            }
        }
    }

    /// Append the contents of the given span to this Data instance.
    mutating func append(contentsOf bytes: RawSpan) {
        bytes.withUnsafeBytes { buffer in
            self.append(contentsOf: buffer)
        }
    }
}

#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
extension InlineArray where Element == UInt8 {
    init<D: DataProtocol>(copying data: D) {
        self.init { outputSpan in
            for region in data.regions {
                region.withUnsafeBytes { bytes in
                    outputSpan.append(contentsOf: bytes.bytes)
                }
            }
        }
    }
}
#endif

#if CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
// Note: Should be provided by SwiftSystem's version of Data. We provide
extension Data {
    var bytes: RawSpan {
        get {
            let buffer = withUnsafeBytes { $0 }
            return _overrideLifetime(buffer.bytes, borrowing: self)
        }
    }

    var mutableBytes: MutableRawSpan {
        mutating get {
            let buffer = withUnsafeMutableBytes { $0 }
            return _overrideLifetime(buffer.mutableBytes, mutating: &self)
        }
    }
}
#endif
#endif // Linux or !SwiftPM
