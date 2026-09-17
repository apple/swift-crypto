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
#if canImport(CryptoKit)
@_exported import CryptoKit
#else

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
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
