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
import Crypto
#elseif (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
import CryptoKit
#else
import Crypto
#endif

enum TestError: Error {
	case unhandled
}

func nullTestVectorForAlgorithm<H: HashFunction>(hashFunction: H.Type) throws -> String {
    switch H.self {
	case is Insecure.SHA1.Type: return "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	case is SHA256.Type: return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	case is SHA384.Type: return "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
	case is SHA512.Type: return "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
	default:
		XCTFail("Unhandled type: \(H.self)")
		throw TestError.unhandled
	}
}

func testVectorForAlgorithm<H: HashFunction>(hashFunction: H.Type) throws -> String {
	switch H.self {
	case is Insecure.SHA1.Type: return "a49b2446a02c645bf419f995b67091253a04a259"
	case is SHA256.Type: return "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
	case is SHA384.Type: return "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
	case is SHA512.Type: return "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
	default:
		XCTFail("Unhandled type: \(H.self)")
		throw TestError.unhandled
	}
}

class DigestsTests: XCTestCase {
    func assertHashFunctionWithVector<H: HashFunction>(hf: H.Type, data: Data, testVector: String, file: StaticString = (#file), line: UInt = #line) throws {
        var h = hf.init()
        h.update(data: data)
        let result = h.finalize()

        let testBytes = try orFail(file: file, line: line) { try Array(hexString: testVector) }

        XCTAssertEqual(testBytes, Array(result), file: file, line: line)
        XCTAssertEqual(Array(H.hash(data: data)), testBytes, file: file, line: line)

        let (contiguousResult, discontiguousResult) = testBytes.asDataProtocols()
        XCTAssert(result == contiguousResult, file: file, line: line)
        XCTAssert(result == discontiguousResult, file: file, line: line)
        XCTAssertFalse(result == DispatchData.empty, file: file, line: line)
    }
    
    func testMD5() throws {
        XCTAssertEqual(Data(Insecure.MD5.hash(data: Data())).count, Insecure.MD5.byteCount)
        XCTAssertEqual(
            Data(Insecure.MD5.hash(data: Data())),
            try Data(hexString: "d41d8cd98f00b204e9800998ecf8427e")
        )
        XCTAssertEqual(
            Data(Insecure.MD5.hash(data: Data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8))),
            try Data(hexString: "8215ef0796a20bcaaae116d3876c664a")
        )
    }

    func testHashFunction<H: HashFunction>(hf: H.Type) throws {
        let data = ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".data(using: String.Encoding.ascii)!)
        try orFail { try assertHashFunctionWithVector(hf: hf, data: data, testVector: try testVectorForAlgorithm(hashFunction: hf)) }
        try orFail { try assertHashFunctionWithVector(hf: hf, data: Data(repeating: 0, count: 0), testVector: try nullTestVectorForAlgorithm(hashFunction: hf)) }
	}

	func testHashFunctions() throws {
        try orFail { try testHashFunction(hf: Insecure.SHA1.self) }
        try orFail { try testHashFunction(hf: SHA256.self) }
        try orFail { try testHashFunction(hf: SHA384.self) }
        try orFail { try testHashFunction(hf: SHA512.self) }
	}

    func testHashFunctionImplementsCoW<H: HashFunction>(hf: H.Type) throws {
        var hf = H()
        hf.update(data: [1, 2, 3, 4])

        var hfCopy = hf
        hf.update(data: [5, 6, 7, 8])
        let digest = hf.finalize()

        hfCopy.update(data: [5, 6, 7, 8])
        let copyDigest = hfCopy.finalize()

        XCTAssertEqual(digest, copyDigest)
    }

    func testHashFunctionsImplementCow() throws {
        try orFail { try testHashFunctionImplementsCoW(hf: Insecure.MD5.self) }
        try orFail { try testHashFunctionImplementsCoW(hf: Insecure.SHA1.self) }
        try orFail { try testHashFunctionImplementsCoW(hf: SHA256.self) }
        try orFail { try testHashFunctionImplementsCoW(hf: SHA384.self) }
        try orFail { try testHashFunctionImplementsCoW(hf: SHA512.self) }
    }
    
    func testBlockSizes() {
        XCTAssertEqual(Insecure.MD5.blockByteCount, 64)
        XCTAssertEqual(Insecure.SHA1.blockByteCount, 64)
        XCTAssertEqual(SHA256.blockByteCount, 64)
        
        XCTAssertEqual(SHA384.blockByteCount, 128)
        XCTAssertEqual(SHA512.blockByteCount, 128)
    }
}
