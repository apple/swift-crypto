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
import Foundation
import XCTest

// Not sure if NSString-bridged "String.init(format:_:)" is available on Linux/Windows.
#if (os(macOS) || os(iOS) || os(tvOS) || os(watchOS)) && CRYPTO_IN_SWIFTPM_FORCE_BUILD_API

@testable import Crypto

class PrettyBytesTests: XCTestCase {
    func testHexString() {
        let random = Data((1...64).map { _ in UInt8.random(in: UInt8.min...UInt8.max)})

        let hexString = random.hexString
        let target = random.map { String(format: "%02x", $0) }.joined()

        XCTAssertEqual(hexString, target)
    }
}

#endif
