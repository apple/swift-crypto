//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftCrypto project authors
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

extension Data {
    // This enhancement can only be present on 6.1 or later because of the
    // absence of https://github.com/swiftlang/swift/pull/76186 in older
    // compilers.
    #if compiler(>=6.1)
    // This overload reduces allocations when used in a chain of infix operations.
    static func + (lhs: consuming Data, rhs: consuming Data) -> Data {
        lhs.append(contentsOf: rhs)
        return lhs
    }
    #endif
}
