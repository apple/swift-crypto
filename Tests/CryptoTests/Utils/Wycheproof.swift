//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import Foundation

struct WycheproofTest<T: Codable>: Codable {
    let algorithm: String
    let numberOfTests: UInt32
    let testGroups: [T]
}

func wycheproofTest<T: Codable>(bundleType: AnyObject, jsonName: String, testFunction: (T) -> Void) {
    #if !CRYPTO_IN_SWIFTPM
    let bundle = Bundle(for: type(of: bundleType))
    let fileURL = bundle.url(forResource: jsonName, withExtension: "json")
    #else
    let testsDirectory: String = URL(fileURLWithPath: "\(#file)").pathComponents.dropLast(3).joined(separator: "/")
    let fileURL: URL? = URL(fileURLWithPath: "\(testsDirectory)/Test Vectors/\(jsonName).json")
    #endif

    let data = try! Data(contentsOf: fileURL!)

    let decoder = JSONDecoder()
    let wpTest = try! decoder.decode(WycheproofTest<T>.self, from: data)

    for group in wpTest.testGroups {
        testFunction(group)
    }
}
