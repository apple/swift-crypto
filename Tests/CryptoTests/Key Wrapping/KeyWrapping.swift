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

class KeyWrappingTests: XCTestCase {
    func testAESWrapTestVectors() throws {
        struct wrapVector {
            let kek: SymmetricKey
            let key: SymmetricKey
            let wrap: Data
        }

        let vector: [wrapVector] = [
            // Corecrypto Test Vector
            wrapVector(kek: try SymmetricKey(data: Data(hexString: "f59782f1dceb0544a8da06b34969b9212b55ce6dcbdd0975a33f4b3f88b538da")),
                       key: try SymmetricKey(data: Data(hexString: "73d33060b5f9f2eb5785c0703ddfa704")),
                       wrap: try Data(hexString: "2e63946ea3c090902fa1558375fdb2907742ac74e39403fc")),
            // IETF Test Vector - Wrap 128 bits of Key Data with a 128-bit KEK
            wrapVector(kek: try SymmetricKey(data: Data(hexString: "000102030405060708090A0B0C0D0E0F")),
                       key: try SymmetricKey(data: Data(hexString: "00112233445566778899AABBCCDDEEFF")),
                       wrap: try Data(hexString: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")),
            // IETF Test Vector - Wrap 128 bits of Key Data with a 192-bit KEK
            wrapVector(kek: try SymmetricKey(data: Data(hexString: "000102030405060708090A0B0C0D0E0F1011121314151617")),
                       key: try SymmetricKey(data: Data(hexString: "00112233445566778899AABBCCDDEEFF")),
                       wrap: try Data(hexString: "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D")),
            // IETF Test Vector - Wrap 128 bits of Key Data with a 256-bit KEK
            wrapVector(kek: try SymmetricKey(data: Data(hexString: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")),
                       key: try SymmetricKey(data: Data(hexString: "00112233445566778899AABBCCDDEEFF")),
                       wrap: try Data(hexString: "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7")),
            // IETF Test Vector - Wrap 192 bits of Key Data with a 192-bit KEK
            wrapVector(kek: try SymmetricKey(data: Data(hexString: "000102030405060708090A0B0C0D0E0F1011121314151617")),
                       key: try SymmetricKey(data: Data(hexString: "00112233445566778899AABBCCDDEEFF0001020304050607")),
                       wrap: try Data(hexString: "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2")),
            // IETF Test Vector - Wrap 192 bits of Key Data with a 256-bit KEK
            wrapVector(kek: try SymmetricKey(data: Data(hexString: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")),
                       key: try SymmetricKey(data: Data(hexString: "00112233445566778899AABBCCDDEEFF0001020304050607")),
                       wrap: try Data(hexString: "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1")),
            // IETF Test Vector - Wrap 256 bits of Key Data with a 256-bit KEK
            wrapVector(kek: try SymmetricKey(data: Data(hexString: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")),
                       key: try SymmetricKey(data: Data(hexString: "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")),
                       wrap: try Data(hexString: "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"))
        ]

        try vector.forEach { e in
            let kek = SymmetricKey(data: e.kek)
            var wrapped = try AES.KeyWrap.wrap(e.key, using: kek)
            XCTAssertEqual(e.wrap, wrapped)
            let unwrapped = try AES.KeyWrap.unwrap(wrapped, using: kek)
            XCTAssertEqual(e.key, unwrapped)

            wrapped[0] = wrapped[0] ^ 1

            XCTAssertThrowsError(try AES.KeyWrap.unwrap(wrapped, using: kek))
        }
    }

    func testWrappingAndUnwrappingEmptinessFails() throws {
        let kek = try SymmetricKey(data: Data(hexString: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"))
        let key = SymmetricKey(data: Data())

        XCTAssertThrowsError(try AES.KeyWrap.wrap(key, using: kek))

        let zeroLengthUnwrapped = Data()
        XCTAssertThrowsError(try AES.KeyWrap.unwrap(zeroLengthUnwrapped, using: kek))
    }

    func testWrappingUnwrappingWithTheEmptyKeyFails() throws {
        let kek = SymmetricKey(data: Data())
        let key = try SymmetricKey(data: Data(hexString: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"))

        XCTAssertThrowsError(try AES.KeyWrap.wrap(key, using: kek))

        let wrappedKey = try Data(hexString: "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")
        XCTAssertThrowsError(try AES.KeyWrap.unwrap(wrappedKey, using: kek))
    }
}

#endif // CRYPTO_IN_SWIFTPM
