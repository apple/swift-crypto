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

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension Optional where Wrapped: DataProtocol {
    func withUnsafeBytes<ReturnValue>(_ body: (UnsafeRawBufferPointer) throws -> ReturnValue) rethrows -> ReturnValue {
        if let self {
            let bytes: ContiguousBytes = self.regions.count == 1 ? self.regions.first! : Array(self)
            return try bytes.withUnsafeBytes { try body($0) }
        } else {
            return try body(UnsafeRawBufferPointer(start: nil, count: 0))
        }
    }
}
