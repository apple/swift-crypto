//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2021 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
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
    func wycheproofTest<T: Codable>(jsonName: String, file: StaticString = #filePath, line: UInt = #line, testFunction: (T) throws -> Void) throws {
        var fileURL = URL(fileURLWithPath: "\(#filePath)")
        for _ in 0..<3 {
            fileURL.deleteLastPathComponent()
        }
        #if compiler(>=6.0)
        if #available(macOS 13, iOS 16, watchOS 9, tvOS 16, visionOS 1, macCatalyst 16, *) {
            fileURL.append(path: "CryptoExtrasVectors", directoryHint: .isDirectory)
            fileURL.append(path: "\(jsonName).json", directoryHint: .notDirectory)
        } else {
            fileURL = fileURL.appendingPathComponent("CryptoExtrasVectors", isDirectory: true)
            fileURL = fileURL.appendingPathComponent("\(jsonName).json", isDirectory: false)
        }
        #else
        fileURL = fileURL.appendingPathComponent("CryptoExtrasVectors", isDirectory: true)
        fileURL = fileURL.appendingPathComponent("\(jsonName).json", isDirectory: false)
        #endif

        let data = try Data(contentsOf: fileURL)

        let decoder = JSONDecoder()
        let wpTest = try decoder.decode(WycheproofTest<T>.self, from: data)

        for group in wpTest.testGroups {
            try testFunction(group)
        }
    }
}
