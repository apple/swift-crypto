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

struct WycheproofTest<T: Codable>: Codable {
    let algorithm: String
    let numberOfTests: UInt32
    let testGroups: [T]
}

extension XCTestCase {
    func wycheproofTest<T: Codable>(bundleType: AnyObject, jsonName: String, file: StaticString = #file, line: UInt = #line, testFunction: (T) throws -> Void) throws {
        #if !CRYPTO_IN_SWIFTPM
        let bundle = Bundle(for: type(of: bundleType))
        let fileURL = bundle.url(forResource: jsonName, withExtension: "json")
        #else
        let testsDirectory: String = URL(fileURLWithPath: "\(#file)").pathComponents.dropLast(3).joined(separator: "/")
        let fileURL: URL? = URL(fileURLWithPath: "\(testsDirectory)/Test Vectors/\(jsonName).json")
        #endif

        let data = try orFail(file: file, line: line) { try Data(contentsOf: unwrap(fileURL, file: file, line: line)) }

        let decoder = JSONDecoder()
        let wpTest = try orFail(file: file, line: line) { try decoder.decode(WycheproofTest<T>.self, from: data) }

        for group in wpTest.testGroups {
            try orFail(file: file, line: line) { try testFunction(group) }
        }
    }
}
