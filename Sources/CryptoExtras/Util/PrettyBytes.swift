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
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
enum ByteHexEncodingErrors: Error {
    case incorrectHexValue
    case incorrectString
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
let charA = UInt8(UnicodeScalar("a").value)
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
let char0 = UInt8(UnicodeScalar("0").value)

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
private func itoh(_ value: UInt8) -> UInt8 {
    return (value > 9) ? (charA + value - 10) : (char0 + value)
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension DataProtocol {
    var hexString: String {
        let hexLen = self.count * 2
        var hexChars = [UInt8](repeating: 0, count: hexLen)
        var offset = 0
        
        self.regions.forEach { (_) in
            for i in self {
                hexChars[Int(offset * 2)] = itoh((i >> 4) & 0xF)
                hexChars[Int(offset * 2 + 1)] = itoh(i & 0xF)
                offset += 1
            }
        }
        
        return String(bytes: hexChars, encoding: .utf8)!
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MutableDataProtocol {
    mutating func appendByte(_ byte: UInt64) {
        withUnsafePointer(to: byte.littleEndian, { self.append(contentsOf: UnsafeRawBufferPointer(start: $0, count: 8)) })
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Data {
    init(hexString: String) throws {
        self.init()

        if hexString.count % 2 != 0 || hexString.count == 0 {
            throw ByteHexEncodingErrors.incorrectString
        }

        let stringBytes: [UInt8] = Array(hexString.lowercased().data(using: String.Encoding.utf8)!)

        for i in stride(from: stringBytes.startIndex, to: stringBytes.endIndex - 1, by: 2) {
            let char1 = stringBytes[i]
            let char2 = stringBytes[i + 1]

            try self.append(htoi(char1) << 4 + htoi(char2))
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Array where Element == UInt8 {
    init(hexString: String) throws {
        self.init()
        
        guard hexString.count.isMultiple(of: 2), !hexString.isEmpty else {
            throw ByteHexEncodingErrors.incorrectString
        }

        let stringBytes: [UInt8] = Array(hexString.data(using: String.Encoding.utf8)!)

        for i in stride(from: stringBytes.startIndex, to: stringBytes.endIndex - 1, by: 2) {
            let char1 = stringBytes[i]
            let char2 = stringBytes[i + 1]

            try self.append(htoi(char1) << 4 + htoi(char2))
        }
    }

}
