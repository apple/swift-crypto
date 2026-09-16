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

#if canImport(CryptoKit)
// Skip tests that require @testable imports of CryptoKit.
#else
@testable import Crypto

extension DERTests {
    func openSSLCoordinateSizeForCurve<Curve: OpenSSLSupportedNISTCurve>(_: Curve.Type) -> Int {
        Curve.coordinateByteCount
    }
}

#endif  // canImport(CryptoKit)
