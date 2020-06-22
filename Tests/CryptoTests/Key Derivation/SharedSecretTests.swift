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

#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// Skip tests that require @testable imports of CryptoKit.
#else
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@testable import CryptoKit
#else
@testable import Crypto
#endif

class SharedSecretTests: XCTestCase {
    func testEqualityWithDataProtocol() throws {
        let testSecret = Array("hello, world".utf8)
        let ss = SharedSecret(ss: SecureBytes(bytes: testSecret))
        let (contiguousSecret, discontiguousSecret) = testSecret.asDataProtocols()

        XCTAssertTrue(ss == contiguousSecret)
        XCTAssertTrue(ss == discontiguousSecret)
        XCTAssertFalse(ss == DispatchData.empty)
    }
}

#endif // (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM
