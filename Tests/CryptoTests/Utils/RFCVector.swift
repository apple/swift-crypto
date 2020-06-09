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

/// This is a not-very-performant decoder of the RFC formatted test vectors.
///
/// It is not intended as a general-purpose example: it does exactly enough to be useful in our
/// tests and nothing more.
struct RFCVectorDecoder {
    private var rfcVectorData: String

    private var decoded: [[String: String]]

    private var index: Int?

    init(bundleType: AnyObject, fileName: String) throws {
        #if !CRYPTO_IN_SWIFTPM
        let bundle = Bundle(for: type(of: bundleType))
        let fileURL = bundle.url(forResource: fileName, withExtension: "txt")
        #else
        let testsDirectory: String = URL(fileURLWithPath: "\(#file)").pathComponents.dropLast(3).joined(separator: "/")
        let fileURL: URL? = URL(fileURLWithPath: "\(testsDirectory)/Test Vectors/\(fileName).txt")
        #endif

        let rfcVectorData = try Data(contentsOf: fileURL!)
        self.rfcVectorData = String(decoding: rfcVectorData, as: Unicode.UTF8.self)
        self.decoded = RFCVectorDecoder.parse(data: self.rfcVectorData)
    }

    init(copyOf decoder: RFCVectorDecoder, index: Int) {
        self.rfcVectorData = decoder.rfcVectorData
        self.decoded = decoder.decoded
        self.index = index
    }

    mutating func decode<T: Decodable>(_ type: T.Type) throws -> T {
        return try T(from: self)
    }

    private static func parse(data: String) -> [[String: String]] {
        // Split on lines.
        var lines = ArraySlice(data.split { $0.isNewline })

        // Strip the leading elements.
        lines = lines.drop(while: { !$0.hasPrefix("COUNT") })

        var decoded = [[String: String]]()

        // Parse the elements
        while let element = lines.parseElement() {
            decoded.append(element)
        }
        assert(lines.count == 0)

        return decoded
    }
}

extension RFCVectorDecoder: Decoder {
    // We never allowed nested coding paths: they are always top-level, within an array.
    var codingPath: [CodingKey] {
        return []
    }

    var userInfo: [CodingUserInfoKey: Any] { return [:] }

    func container<Key>(keyedBy type: Key.Type) throws -> KeyedDecodingContainer<Key> where Key: CodingKey {
        guard let index = self.index else {
            throw Error.topLevelKeyedContainersNotSupported
        }

        return KeyedDecodingContainer(_KeyedDecodingContainer(forElement: self.decoded[index], path: [], decoder: self))
    }

    func unkeyedContainer() throws -> UnkeyedDecodingContainer {
        guard self.index == nil else {
            throw Error.nestedContainersNotSupported
        }
        return UnkeyedContainer(elements: self.decoded, decoder: self)
    }

    func singleValueContainer() throws -> SingleValueDecodingContainer {
        guard self.index == nil else {
            throw Error.nestedContainersNotSupported
        }
        return SingleValueContainer()
    }
}

extension RFCVectorDecoder {
    struct _KeyedDecodingContainer<Key: CodingKey>: KeyedDecodingContainerProtocol {
        private var element: [String: String]

        private var decoder: RFCVectorDecoder

        var codingPath: [CodingKey]

        var allKeys: [Key] {
            self.element.keys.compactMap { Key(stringValue: $0) }
        }

        init(forElement element: [String: String], path: [CodingKey], decoder: RFCVectorDecoder) {
            self.element = element
            self.codingPath = path
            self.decoder = decoder
        }

        func contains(_ key: Key) -> Bool {
            return self.element.keys.contains(key.stringValue)
        }

        func decode<T: Decodable>(_ type: T.Type, forKey key: Key) throws -> T {
            guard let stringResult = self.element[key.stringValue] else {
                throw Error.missingKey
            }

            switch type {
            case is String.Type:
                return stringResult as! T
            case is [UInt8].Type:
                if stringResult.count == 0 {
                    return [UInt8]() as! T
                } else {
                    return try Array(hexString: stringResult) as! T
                }
            case is Int.Type:
                return Int(stringResult, radix: 10)! as! T
            default:
                throw Error.attemptToDecodeInvalidType
            }
        }

        func decodeNil(forKey key: Key) throws -> Bool {
            return false  // No support for nil today.
        }

        func nestedContainer<NestedKey>(keyedBy type: NestedKey.Type, forKey key: Key) throws -> KeyedDecodingContainer<NestedKey> where NestedKey: CodingKey {
            throw Error.nestedContainersNotSupported
        }

        func nestedUnkeyedContainer(forKey key: Key) throws -> UnkeyedDecodingContainer {
            throw Error.nestedContainersNotSupported
        }

        func superDecoder() throws -> Decoder {
            return decoder
        }

        func superDecoder(forKey key: Key) throws -> Decoder {
            return decoder
        }
    }
}

extension RFCVectorDecoder {
    struct UnkeyedContainer: UnkeyedDecodingContainer {
        private var elements: [[String: String]]

        private var decoder: RFCVectorDecoder

        var currentIndex: Int

        var codingPath: [CodingKey] {
            // This is always at the root
            return []
        }

        var count: Int? {
            return elements.count
        }

        var isAtEnd: Bool {
            return self.currentIndex == self.elements.endIndex
        }

        init(elements: [[String: String]], decoder: RFCVectorDecoder) {
            self.elements = elements
            self.decoder = decoder
            self.currentIndex = elements.startIndex
        }

        mutating func decode<T>(_ type: T.Type) throws -> T where T: Decodable {
            let index = self.currentIndex
            self.elements.formIndex(after: &self.currentIndex)
            return try type.init(from: RFCVectorDecoder(copyOf: self.decoder, index: index))
        }

        func decodeNil() throws -> Bool {
            return false  // No support for nil today.
        }

        mutating func nestedContainer<NestedKey>(keyedBy type: NestedKey.Type) throws -> KeyedDecodingContainer<NestedKey> where NestedKey: CodingKey {
            let index = self.currentIndex
            self.elements.formIndex(after: &self.currentIndex)
            return try RFCVectorDecoder(copyOf: self.decoder, index: index).container(keyedBy: type)
        }

        func nestedUnkeyedContainer() throws -> UnkeyedDecodingContainer {
            throw Error.nestedContainersNotSupported
        }

        func superDecoder() throws -> Decoder {
            return decoder
        }
    }
}

extension RFCVectorDecoder {
    // We don't support single values, but we need the type. It's unconstructable.
    struct SingleValueContainer: SingleValueDecodingContainer {
        var codingPath: [CodingKey] {
            // This is always at the root
            return []
        }

        init() {
            fatalError("SingleValueContainer is unsupported")
        }

        func decode<T>(_ type: T.Type) throws -> T where T: Decodable {
            fatalError("SingleValueContainer is unsupported")
        }

        func decodeNil() -> Bool {
            fatalError("SingleValueContainer is unsupported")
        }

        func nestedContainer<NestedKey>(keyedBy type: NestedKey.Type) throws -> KeyedDecodingContainer<NestedKey> where NestedKey: CodingKey {
            fatalError("SingleValueContainer is unsupported")
        }

        func nestedUnkeyedContainer() throws -> UnkeyedDecodingContainer {
            fatalError("SingleValueContainer is unsupported")
        }

        func superDecoder() throws -> Decoder {
            fatalError("SingleValueContainer is unsupported")
        }
    }
}

extension RFCVectorDecoder {
    enum Error: Swift.Error {
        case attemptToDecodeInvalidType
        case missingKey
        case nestedContainersNotSupported
        case topLevelKeyedContainersNotSupported
    }
}

extension ArraySlice where Element == Substring {
    /// Parses a single block. A block runs from a COUNT declaration to a COUNT declaration,
    /// includes the first and excludes the last.
    mutating func parseElement() -> [String: String]? {
        // We need to drop first here as the first index with COUNT is going to be startIndex.
        let nextCountIndex = self.dropFirst().firstIndex(where: { $0.hasPrefix("COUNT") }) ?? self.endIndex

        // Grab the elements, removing any that are either empty strings, begin with # or [ characters,
        // or begin with whitespace (these are used in some cases and we don't want them). This is a brute
        // force comparison, but it's test code, don't worry about it.
        let elements: [(String, String)] = self[..<nextCountIndex].filter { string in
            return (string.trimmingCharacters(in: .whitespaces).count > 0 &&
                    !string.hasPrefix("#") &&
                    !string.hasPrefix("[") &&
                    !string.first!.isWhitespace)
        }.map { string in
            let split = string.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            assert(split.count == 2)
            return (String(split.first!.trimmingCharacters(in: .whitespaces)), String(split.last!).trimmingCharacters(in: .whitespaces))
        }

        // Slice off the section we've parsed.
        self = self[nextCountIndex...]

        // Now we split each element on = and turn them into a map, omitting the map when it's empty.
        let mappedElements = Dictionary(uniqueKeysWithValues: elements)
        if mappedElements.count > 0 {
            return mappedElements
        } else {
            return nil
        }
    }
}
