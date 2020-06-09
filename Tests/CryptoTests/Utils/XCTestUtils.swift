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
import XCTest

// Xcode 11.4 catches errors thrown during tests and reports them on the
// correct line. But Linux and older Xcodes do not, so we need to use this
// wrapper as long as those platforms are supported.
func orFail<T>(file: StaticString = #file, line: UInt = #line, _ closure: () throws -> T) throws -> T {
    func wrapper<T>(_ closure: () throws -> T, file: StaticString, line: UInt) throws -> T {
        do {
            return try closure()
        } catch {
            XCTFail("Function threw error: \(error)", file: file, line: line)
            throw error
        }
    }

    #if compiler(>=5.2) && canImport(Darwin)
        if #available(macOS 10.15.4, macCatalyst 13.4, iOS 13.4, tvOS 13.4, watchOS 6.0, *) {
            return try closure()
        } else {
            return try wrapper(closure, file: file, line: line)
        }
    #else
        return try wrapper(closure, file: file, line: line)
    #endif
}

extension XCTestCase {
    struct OptionalUnwrappingError: Error {
        let file: StaticString
        let line: UInt
    }

    /// Unwraps the given optional value, or if it is nil, throws an error and
    /// registers an XCTest failure. Meant to be used in a test method that has
    /// been marked as `throws`.
    /// - Note: this is a replacement for `XCTUnwrap`, which is not availble
    /// in SPM command line builds as of this writing: <https://bugs.swift.org/browse/SR-11501>
    func unwrap<T>(_ optional: T?, file: StaticString = (#file), line: UInt = #line) throws -> T {
        guard let wrapped = optional else {
            XCTFail("Optional was nil", file: file, line: line)
            throw OptionalUnwrappingError(file: file, line: line)
        }

        return wrapped
    }

}
