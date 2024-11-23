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

import XCTest

@testable import _CryptoExtras

@available(macOS 14.0, *)
final class MLKEMTests: XCTestCase {
    func testMLKEMEncapDecap() throws {
        let privateKey = MLKEM.PrivateKey()
        let publicKey = privateKey.publicKey
        let encapsulationResult = publicKey.encapsulate()
        let sharedSecret = try privateKey.decapsulate(encapsulationResult.encapsulated)
        XCTAssertEqual(sharedSecret, encapsulationResult.sharedSecret)
    }
}