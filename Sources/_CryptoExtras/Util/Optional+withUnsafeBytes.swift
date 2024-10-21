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

import Foundation

extension Optional where Wrapped == ContiguousBytes {
    func withUnsafeBytes<ReturnValue>(_ body: (UnsafeRawBufferPointer) throws -> ReturnValue) rethrows -> ReturnValue {
        if let self {
            return try self.withUnsafeBytes { try body($0) }
        } else {
            return try body(UnsafeRawBufferPointer(start: nil, count: 0))
        }
    }
}