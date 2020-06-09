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

final class SecureBytesTests: XCTestCase {
    func testBasicSanity() {
        var first = SecureBytes()
        var second = SecureBytes()

        first.append(Data("hello".utf8))
        second.append(Data("hello".utf8))

        XCTAssertEqual(first, second)

        first.append(Data("world".utf8))
        second.append(Data("wrold".utf8))
        XCTAssertNotEqual(first, second)
    }

    func testSimpleCollection() {
        let base = SecureBytes(0..<100)
        XCTAssertEqual(base.count, 100)
        XCTAssertEqual(Array(base), Array(0..<100))
        XCTAssertEqual(base.first, 0)
        XCTAssertEqual(base.last, 99)
        XCTAssertEqual(base.reduce(Int(0)) { Int($0) + Int($1) }, 4950)
    }

    func testSimpleBidirectionalCollection() {
        let base = SecureBytes(0..<100)
        let reversed = base.reversed()
        XCTAssertEqual(Array(reversed), Array(stride(from: 99, through: 0, by: -1)))
    }

    func testSimpleRandomAccessCollection() {
        // Not easy to test this, just try to move the indices around a bit.
        let base = SecureBytes(0..<100)
        let aMiddleIndex = base.index(base.startIndex, offsetBy: 48)
        let aDifferentMiddleIndex = base.index(aMiddleIndex, offsetBy: 5)
        XCTAssertEqual(base.distance(from: aMiddleIndex, to: aDifferentMiddleIndex), 5)

        XCTAssertEqual(base[aMiddleIndex], 48)
        XCTAssertEqual(base[aDifferentMiddleIndex], 48 + 5)
    }

    func testSimpleMutableCollection() {
        var base = SecureBytes(repeating: 0, count: 5)
        let offset = base.index(base.startIndex, offsetBy: 2)
        base[offset] = 5
        XCTAssertEqual(Array(base), [0, 0, 5, 0, 0])
    }

    func testSimpleRangeReplaceableCollection() {
        // This test validates RangeReplaceableCollection and the value semantics all at once.
        let base = SecureBytes(repeating: 0, count: 10)
        let baseBytes = Array(repeating: UInt8(0), count: 10)

        // There are a few ways we can "replace" a subrange. The first is to extend at the front by appending.
        var copy = base
        copy.insert(contentsOf: [1, 2, 3, 4], at: copy.startIndex)
        XCTAssertEqual(Array(copy), [1, 2, 3, 4] + baseBytes)
        XCTAssertEqual(Array(base), baseBytes)
        XCTAssertNotEqual(copy, base)

        // The second is to extend at the back.
        copy = base
        copy.append(contentsOf: [1, 2, 3, 4])
        XCTAssertEqual(Array(copy), baseBytes + [1, 2, 3, 4])
        XCTAssertEqual(Array(base), baseBytes)
        XCTAssertNotEqual(copy, base)

        // The third is to "shrink" by replacing a subrange in the middle.
        copy = base
        var aMiddleIndex = copy.index(copy.startIndex, offsetBy: 2)
        var aDifferentMiddleIndex = copy.index(aMiddleIndex, offsetBy: 5)
        copy.removeSubrange(aMiddleIndex..<aDifferentMiddleIndex)
        XCTAssertEqual(copy.count, 5)
        XCTAssertEqual(Array(copy), [0, 0, 0, 0, 0])
        XCTAssertEqual(Array(base), baseBytes)
        XCTAssertNotEqual(copy, base)

        // The fourth is to replace a fixed size subrange with a different subrange of the same size.
        copy = base
        aMiddleIndex = copy.index(copy.startIndex, offsetBy: 2)
        aDifferentMiddleIndex = copy.index(aMiddleIndex, offsetBy: 5)
        copy.replaceSubrange(aMiddleIndex..<aDifferentMiddleIndex, with: [1, 2, 3, 4, 5])
        XCTAssertEqual(copy.count, 10)
        XCTAssertEqual(Array(copy), [0, 0, 1, 2, 3, 4, 5, 0, 0, 0])
        XCTAssertEqual(Array(base), baseBytes)
        XCTAssertNotEqual(copy, base)

        // The fifth is to make the storage bigger.
        copy = base
        aMiddleIndex = copy.index(copy.startIndex, offsetBy: 2)
        aDifferentMiddleIndex = copy.index(aMiddleIndex, offsetBy: 5)
        copy.replaceSubrange(aMiddleIndex..<aDifferentMiddleIndex, with: [1, 2, 3, 4, 5, 6, 7])
        XCTAssertEqual(copy.count, 12)
        XCTAssertEqual(Array(copy), [0, 0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0])
        XCTAssertEqual(Array(base), baseBytes)
        XCTAssertNotEqual(copy, base)
    }

    func testResizingByMakingLarger() {
        var base = SecureBytes(count: 12)
        XCTAssertGreaterThanOrEqual(base.backing.capacity, 16)
        XCTAssertEqual(base.count, 12)

        base.append(contentsOf: 0..<16)
        XCTAssertGreaterThanOrEqual(base.backing.capacity, 32)
        XCTAssertEqual(base.count, 28)

        base.append(contentsOf: 0..<4)
        XCTAssertGreaterThanOrEqual(base.backing.capacity, 32)
        XCTAssertEqual(base.count, 32)
    }

    func testCountInitializerGeneratesSomewhatRandomData() {
        let base = SecureBytes(count: 16)
        XCTAssertGreaterThanOrEqual(base.backing.capacity, 16)
        XCTAssertEqual(base.count, 16)
        XCTAssertNotEqual(Array(repeating: UInt8(0), count: 16), Array(base))
    }

    func testBackingBytesAreAppropriatelySized() {
        var base = SecureBytes(repeating: 0, count: 10)
        XCTAssertGreaterThanOrEqual(base.backing.capacity, 16)

        base.withUnsafeBytes { XCTAssertEqual($0.count, 10) }
        base.withUnsafeMutableBytes { XCTAssertEqual($0.count, 10) }
        base.backing._withVeryUnsafeMutableBytes { XCTAssertGreaterThanOrEqual($0.count, 16) }
    }

    func testTheresOnlyOneRegion() {
        var base = SecureBytes()
        base.append(Data("hello".utf8))
        base.append(Data("world".utf8))
        XCTAssertEqual(base.regions.count, 1)
    }

    func testScaryInitializer() {
        let base = SecureBytes(unsafeUninitializedCapacity: 5) { (scaryPointer, initializedCapacity) in
            XCTAssertEqual(scaryPointer.count, 5)
            scaryPointer.storeBytes(of: UInt32(0x01020304).bigEndian, as: UInt32.self)
            initializedCapacity = 4
        }

        XCTAssertGreaterThanOrEqual(base.backing.capacity, 8)
        XCTAssertEqual(Array(base), [1, 2, 3, 4])

        func testThrowingInitialization() throws {
            _ = try SecureBytes(unsafeUninitializedCapacity: 5) { (_, _) in
                throw CryptoKitError.incorrectKeySize
            }
        }
        XCTAssertThrowsError(try testThrowingInitialization()) { error in
            guard case .some(.incorrectKeySize) = error as? CryptoKitError else {
                XCTFail("unexpected error: \(error)")
                return
            }
        }
    }

    func testAppendingDataPerformsACoW() {
        var base = SecureBytes(repeating: 0, count: 10)
        let copy = base

        base.append("Hello, world".utf8)

        XCTAssertEqual(base.count, 22)
        XCTAssertEqual(copy.count, 10)
    }

    func testRequestingAMutablePointerPerformsACoW() {
        var base = SecureBytes(repeating: 0, count: 10)
        let copy = base

        base.withUnsafeMutableBytes {
            $0.storeBytes(of: UInt32(0x01020304).bigEndian, toByteOffset: 4, as: UInt32.self)
        }

        XCTAssertEqual(Array(base), [0, 0, 0, 0, 1, 2, 3, 4, 0, 0])
        XCTAssertEqual(Array(copy), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    func testDataCausesCoWs() {
        var base = SecureBytes(repeating: 0, count: 10)
        let copy = Data(base)
        XCTAssertEqual(base.count, copy.count)

        base.append("Hello, world".utf8)

        XCTAssertEqual(base.count, 22)
        XCTAssertEqual(copy.count, 10)
    }

    func testDataFromSlice() {
        var base = SecureBytes(0..<10)
        let copy = Data(base.prefix(5))
        XCTAssertEqual(Array(copy), [0, 1, 2, 3, 4])

        base.append("Hello, world".utf8)

        XCTAssertEqual(base.count, 22)
        XCTAssertEqual(Array(copy), [0, 1, 2, 3, 4])
    }
}

#endif // (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM
