//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import XCTest

extension XCTestCase {
    /// Takes a throwing closure. Returns the result if the closure succeeds.
    /// If the closure throws, this method registers an XCTest failure and rethrows the error.
    /// - Note: closure comes last so that trailing closure syntax works.
    func orFail<T>(file: StaticString = #file, line: UInt = #line, _ closure: () throws -> T) throws -> T {
        do {
            return try closure()
        }
        catch {
            XCTFail("Function threw error: \(error)", file: file, line: line)
            throw error
        }
    }
}
