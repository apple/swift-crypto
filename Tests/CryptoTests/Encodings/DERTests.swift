//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import XCTest

#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
// Skip tests that require @testable imports of CryptoKit.
#else
#if !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@testable import CryptoKit
#else
@testable import Crypto
#endif

class DERTests: XCTestCase {
    func testEncodeDecodeECDSASignature() throws {
        let pointSize = self.coordinateSizeForCurve(P256.self)
        let r = self.randomBytes(count: pointSize)
        let s = self.randomBytes(count: pointSize)
        
        let signature = try orFail { try P256.Signing.ECDSASignature(rawRepresentation: (r + s)) }
        
        XCTAssertEqual(Data(r + s), signature.rawRepresentation)
        
        let der = try orFail { try P256.Signing.ECDSASignature(derRepresentation: signature.derRepresentation) }
        
        XCTAssertEqual(der.rawRepresentation, signature.rawRepresentation)
        XCTAssertEqual(der.derRepresentation, signature.derRepresentation)
        
        XCTAssertEqual(der.rawRepresentation.count, 64)
    }

    func coordinateSizeForCurve<Curve: SupportedCurveDetailsImpl>(_ curve: Curve.Type) -> Int {
        #if !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        return self.coreCryptoCoordinateSizeForCurve(curve)
        #else
        return self.openSSLCoordinateSizeForCurve(curve)
        #endif
    }

    func randomBytes(count: Int) -> [UInt8] {
        #if canImport(Darwin) || os(Linux) || os(Android) || os(Windows) || os(FreeBSD)
        var rng = SystemRandomNumberGenerator()
        return (0..<count).map { _ in rng.next() }
        #else
        fatalError("No secure random number generator on this platform.")
        #endif
    }
}
#endif // CRYPTO_IN_SWIFTPM
