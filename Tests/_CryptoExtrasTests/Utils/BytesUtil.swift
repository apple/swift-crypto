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

enum ByteHexEncodingErrors: Error {
    case incorrectHexValue
    case incorrectString
}

let charA = UInt8(UnicodeScalar("a").value)
let char0 = UInt8(UnicodeScalar("0").value)

private func itoh(_ value: UInt8) -> UInt8 {
    return (value > 9) ? (charA + value - 10) : (char0 + value)
}

private func htoi(_ value: UInt8) throws -> UInt8 {
    switch value {
    case char0...char0 + 9:
        return value - char0
    case charA...charA + 5:
        return value - charA + 10
    default:
        throw ByteHexEncodingErrors.incorrectHexValue
    }
}

extension Array where Element == UInt8 {
    init(hexString: String) throws {
        self.init()
        
        guard hexString.count.isMultiple(of: 2), !hexString.isEmpty else {
            throw ByteHexEncodingErrors.incorrectString
        }

        let stringBytes: [UInt8] = Array(hexString.data(using: String.Encoding.utf8)!)

        for i in 0...((hexString.count / 2) - 1) {
            let char1 = stringBytes[2 * i]
            let char2 = stringBytes[2 * i + 1]

            try self.append(htoi(char1) << 4 + htoi(char2))
        }
    }

}

extension DataProtocol {
    var hexString: String {
        get {
            let hexLen = self.count * 2
            let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: hexLen)
            var offset = 0

            self.regions.forEach { (_) in
                for i in self {
                    ptr[Int(offset * 2)] = itoh((i >> 4) & 0xF)
                    ptr[Int(offset * 2 + 1)] = itoh(i & 0xF)
                    offset += 1
                }
            }

            return String(bytesNoCopy: ptr, length: hexLen, encoding: .utf8, freeWhenDone: true)!
        }
    }
}

extension Data {
    init(hexString: String) throws {
        self.init()

        if hexString.count == 0 {
            return
        }

        if hexString.count % 2 != 0 {
            throw ByteHexEncodingErrors.incorrectString
        }

        let stringBytes: [UInt8] = Array(hexString.data(using: String.Encoding.utf8)!)

        for i in 0...((hexString.count / 2) - 1) {
            let char1 = stringBytes[2 * i]
            let char2 = stringBytes[2 * i + 1]

            try self.append(htoi(char1) << 4 + htoi(char2))
        }
    }

}
