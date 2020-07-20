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
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
import Foundation

// This module implements "just enough" ASN.1. Specifically, we implement exactly enough ASN.1 DER parsing to handle
// the following use-cases:
//
// 1. Being able to parse the SPKI format for EC public keys
// 2. Being able to parse the PKCS#8 format for EC private keys
// 3. Being able to parse the SEC 1 format for EC private keys (produced by `openssl ec`)
//
// Let's talk about the DER encoding of ASN.1. DER is fundamentally a TLV (type length value) encoding. Each element is
// made of up some bytes that identify its type, some bytes that identify the length, and then the contents. In the full
// scheme of ASN.1 we care about a lot of things about its structure, but for our case we only care about a few kinds of
// tag. To work out the tag we need, we can look at the X.509 representation of an EC key public key, from RFC 5480 (for case 1), as
// well as the SEC 1 format for private keys and the PKCS#8 format for private keys.
//
// ### RFC 5480 SPKI:
//
// SubjectPublicKeyInfo  ::=  SEQUENCE  {
//   algorithm         AlgorithmIdentifier,
//   subjectPublicKey  BIT STRING
// }
//
// ### SEC 1
//
// For private keys, SEC 1 uses:
//
// ECPrivateKey ::= SEQUENCE {
//   version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
//   privateKey OCTET STRING,
//   parameters [0] EXPLICIT ECDomainParameters OPTIONAL,
//   publicKey [1] EXPLICIT BIT STRING OPTIONAL
// }
//
// ### PKCS#8
//
// For PKCS#8 we need the following for the private key:
//
// PrivateKeyInfo ::= SEQUENCE {
//   version                   Version,
//   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
//   privateKey                PrivateKey,
//   attributes           [0]  IMPLICIT Attributes OPTIONAL }
//
// Version ::= INTEGER
//
// PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
//
// PrivateKey ::= OCTET STRING
//
// Attributes ::= SET OF Attribute
//
// ### Common
//
// Several of the above use formats defined here:
//
// AlgorithmIdentifier  ::=  SEQUENCE  {
//   algorithm   OBJECT IDENTIFIER,
//   parameters  ANY DEFINED BY algorithm OPTIONAL
// }
//
// ECParameters ::= CHOICE {
//   namedCurve         OBJECT IDENTIFIER
//   -- implicitCurve   NULL
//   -- specifiedCurve  SpecifiedECDomain
// }
//
// For us, we expect the ECParameters structure to be using the namedCurve representation only: as we support only the NIST curves with ASN.1
// there is no reason for the curve to ever not be named.
//
// Conveniently, this requires only a few data types from us: SEQUENCE, BIT STRING, OCTET STRING, and OBJECT IDENTIFIER. All three are
// universal objects for ASN.1. Their relevant characteristics are:
//
// ┌───────────────────┬────────────┬────────────────────────────────────────────────┬────────────────┬───────────┐
// │ Name              │ Tag Number │ Primitive                                      │ Encoding Class │ Tag Bytes │
// ├───────────────────┼────────────┼────────────────────────────────────────────────┼────────────────┼───────────┤
// │ SEQUENCE          │       0x10 │                                              N │ Universal      │      0x30 │
// │ BIT STRING        │       0x03 │   Y (we don't support constructed bit strings) │ Universal      │      0x03 │
// │ OBJECT IDENTIFIER │       0x06 │                                              Y │ Universal      │      0x06 │
// | OCTET STRING      |       0x04 | Y (we don't support constructed octet strings) | Universal      |      0x04 |
// | INTEGER           |       0x02 |                                              Y | Universal      |      0x02 |
// └───────────────────┴────────────┴────────────────────────────────────────────────┴────────────────┴───────────┘
//
// The subjectPublicKey is required to be in x9.62 format, either compressed or uncompressed, so we can pass it directly to the
// initializers for CryptoKit once we've done the extraction.
//
// This is the complete set of things we need to be able to parse. To make our lives easier we try to parse this set of things somewhat
// generally: that is, we don't hard-code special knowledge of these formats as part of the parsing process. Instead we have written a
// parser that can divide the world of ASN.1 into parseable chunks, and then we try to decode specific formats from those chunks. This
// allows us to extend things in the future without too much pain.
internal enum ASN1 { }

// MARK: - Parser Node
extension ASN1 {
    /// An `ASN1ParserNode` is a representation of a parsed ASN.1 TLV section. An `ASN1ParserNode` may be primitive, or may be composed of other `ASN1ParserNode`s.
    /// In our representation, we keep track of this by storing a node "depth", which allows rapid forward and backward scans to hop over sections
    /// we're uninterested in.
    ///
    /// This type is not exposed to users of the API: it is only used internally for implementation of the user-level API.
    fileprivate struct ASN1ParserNode {
        /// The identifier.
        var identifier: ASN1Identifier

        /// The depth of this node.
        var depth: Int

        /// The data bytes for this node, if it is primitive.
        var dataBytes: ArraySlice<UInt8>?
    }
}

extension ASN1.ASN1ParserNode: Hashable { }

extension ASN1.ASN1ParserNode: CustomStringConvertible {
    var description: String {
        return "ASN1.ASN1ParserNode(identifier: \(self.identifier), depth: \(self.depth), dataBytes: \(self.dataBytes?.count ?? 0))"
    }
}

// MARK: - Sequence
extension ASN1 {
    /// Parse the node as an ASN.1 sequence.
    internal static func sequence<T>(_ node: ASN1Node, _ builder: (inout ASN1.ASN1NodeCollection.Iterator) throws -> T) throws -> T {
        guard node.identifier == .sequence, case .constructed(let nodes) = node.content else {
            throw CryptoKitASN1Error.unexpectedFieldType
        }

        var iterator = nodes.makeIterator()

        let result = try builder(&iterator)

        guard iterator.next() == nil else {
            throw CryptoKitASN1Error.invalidASN1Object
        }

        return result
    }
}

// MARK: - Optional explicitly tagged
extension ASN1 {
    /// Parses an optional explicitly tagged element. Throws on a tag mismatch, returns nil if the element simply isn't there.
    ///
    /// Expects to be used with the `ASN1.sequence` helper function.
    internal static func optionalExplicitlyTagged<T>(_ nodes: inout ASN1.ASN1NodeCollection.Iterator, tagNumber: Int, tagClass: ASN1.ASN1Identifier.TagClass, _ builder: (ASN1Node) throws -> T) throws -> T? {
        var localNodesCopy = nodes
        guard let node = localNodesCopy.next() else {
            // Node not present, return nil.
            return nil
        }

        let expectedNodeID = ASN1.ASN1Identifier(explicitTagWithNumber: tagNumber, tagClass: tagClass)
        assert(expectedNodeID.constructed)
        guard node.identifier == expectedNodeID else {
            // Node is a mismatch, with the wrong tag. Our optional isn't present.
            return nil
        }

        // We have the right optional, so let's consume it.
        nodes = localNodesCopy

        // We expect a single child.
        guard case .constructed(let nodes) = node.content else {
            // This error is an internal parser error: the tag above is always constructed.
            preconditionFailure("Explicit tags are always constructed")
        }

        var nodeIterator = nodes.makeIterator()
        guard let child = nodeIterator.next(), nodeIterator.next() == nil else {
            throw CryptoKitASN1Error.invalidASN1Object
        }

        return try builder(child)
    }
}

// MARK: - Parsing
extension ASN1 {
    /// A parsed representation of ASN.1.
    fileprivate struct ASN1ParseResult {
        private static let maximumNodeDepth = 10

        var nodes: ArraySlice<ASN1ParserNode>

        private init(_ nodes: ArraySlice<ASN1ParserNode>) {
            self.nodes = nodes
        }

        fileprivate static func parse(_ data: ArraySlice<UInt8>) throws -> ASN1ParseResult {
            var data = data
            var nodes = [ASN1ParserNode]()
            nodes.reserveCapacity(16)

            try parseNode(from: &data, depth: 1, into: &nodes)
            guard data.count == 0 else {
                throw CryptoKitASN1Error.invalidASN1Object
            }
            return ASN1ParseResult(nodes[...])
        }

        /// Parses a single ASN.1 node from the data and appends it to the buffer. This may recursively
        /// call itself when there are child nodes for constructed nodes.
        private static func parseNode(from data: inout ArraySlice<UInt8>, depth: Int, into nodes: inout [ASN1ParserNode]) throws {
            guard depth <= ASN1.ASN1ParseResult.maximumNodeDepth else {
                // We defend ourselves against stack overflow by refusing to allocate more than 10 stack frames to
                // the parsing.
                throw CryptoKitASN1Error.invalidASN1Object
            }

            guard let rawIdentifier = data.popFirst() else {
                throw CryptoKitASN1Error.truncatedASN1Field
            }

            let identifier = try ASN1Identifier(rawIdentifier: rawIdentifier)
            guard let wideLength = try data.readASN1Length() else {
                throw CryptoKitASN1Error.truncatedASN1Field
            }

            // UInt is sometimes too large for us!
            guard let length = Int(exactly: wideLength) else {
                throw CryptoKitASN1Error.invalidASN1Object
            }

            var subData = data.prefix(length)
            data = data.dropFirst(length)

            guard subData.count == length else {
                throw CryptoKitASN1Error.truncatedASN1Field
            }

            if identifier.constructed {
                nodes.append(ASN1ParserNode(identifier: identifier, depth: depth, dataBytes: nil))
                while subData.count > 0 {
                    try parseNode(from: &subData, depth: depth + 1, into: &nodes)
                }
            } else {
                nodes.append(ASN1ParserNode(identifier: identifier, depth: depth, dataBytes: subData))
            }
        }
    }
}

extension ASN1.ASN1ParseResult: Hashable { }

extension ASN1 {
    static func parse(_ data: [UInt8]) throws -> ASN1Node {
        return try parse(data[...])
    }

    static func parse(_ data: ArraySlice<UInt8>) throws -> ASN1Node {
        var result = try ASN1ParseResult.parse(data)

        // There will always be at least one node if the above didn't throw, so we can safely just removeFirst here.
        let firstNode = result.nodes.removeFirst()

        let rootNode: ASN1Node
        if firstNode.identifier.constructed {
            // We need to feed it the next set of nodes.
            let nodeCollection = result.nodes.prefix { $0.depth > firstNode.depth }
            result.nodes = result.nodes.dropFirst(nodeCollection.count)
            rootNode = ASN1.ASN1Node(identifier: firstNode.identifier, content: .constructed(.init(nodes: nodeCollection, depth: firstNode.depth)))
        } else {
            rootNode = ASN1.ASN1Node(identifier: firstNode.identifier, content: .primitive(firstNode.dataBytes!))
        }

        precondition(result.nodes.count == 0, "ASN1ParseResult unexpectedly allowed multiple root nodes")

        return rootNode
    }
}

// MARK: - ASN1NodeCollection
extension ASN1 {
    /// Represents a collection of ASN.1 nodes contained in a constructed ASN.1 node.
    ///
    /// Constructed ASN.1 nodes are made up of multiple child nodes. This object represents the collection of those child nodes.
    /// It allows us to lazily construct the child nodes, potentially skipping over them when we don't care about them.
    internal struct ASN1NodeCollection {
        private var nodes: ArraySlice<ASN1ParserNode>

        private var depth: Int

        fileprivate init(nodes: ArraySlice<ASN1ParserNode>, depth: Int) {
            self.nodes = nodes
            self.depth = depth

            precondition(self.nodes.allSatisfy({ $0.depth > depth }))
            if let firstDepth = self.nodes.first?.depth {
                precondition(firstDepth == depth + 1)
            }
        }
    }
}

extension ASN1.ASN1NodeCollection: Sequence {
    struct Iterator: IteratorProtocol {
        private var nodes: ArraySlice<ASN1.ASN1ParserNode>
        private var depth: Int

        fileprivate init(nodes: ArraySlice<ASN1.ASN1ParserNode>, depth: Int) {
            self.nodes = nodes
            self.depth = depth
        }

        mutating func next() -> ASN1.ASN1Node? {
            guard let nextNode = self.nodes.popFirst() else {
                return nil
            }

            assert(nextNode.depth == self.depth + 1)
            if nextNode.identifier.constructed {
                // We need to feed it the next set of nodes.
                let nodeCollection = self.nodes.prefix { $0.depth > nextNode.depth }
                self.nodes = self.nodes.dropFirst(nodeCollection.count)
                return ASN1.ASN1Node(identifier: nextNode.identifier, content: .constructed(.init(nodes: nodeCollection, depth: nextNode.depth)))
            } else {
                // There must be data bytes here, even if they're empty.
                return ASN1.ASN1Node(identifier: nextNode.identifier, content: .primitive(nextNode.dataBytes!))
            }
        }
    }

    func makeIterator() -> Iterator {
        return Iterator(nodes: self.nodes, depth: self.depth)
    }
}

// MARK: - ASN1Node
extension ASN1 {
    /// An `ASN1Node` is a single entry in the ASN.1 representation of a data structure.
    ///
    /// Conceptually, an ASN.1 data structure is rooted in a single node, which may itself contain zero or more
    /// other nodes. ASN.1 nodes are either "constructed", meaning they contain other nodes, or "primitive", meaning they
    /// store a base data type of some kind.
    ///
    /// In this way, ASN.1 objects tend to form a "tree", where each object is represented by a single top-level constructed
    /// node that contains other objects and primitives, eventually reaching the bottom which is made up of primitive objects.
    internal struct ASN1Node {
        internal var identifier: ASN1Identifier

        internal var content: Content
    }
}

// MARK: - ASN1Node.Content
extension ASN1.ASN1Node {
    /// The content of a single ASN1Node.
    enum Content {
        case constructed(ASN1.ASN1NodeCollection)
        case primitive(ArraySlice<UInt8>)
    }
}

// MARK: - Serializing
extension ASN1 {
    struct Serializer {
        private(set) var serializedBytes: [UInt8]

        init() {
            // We allocate a 1kB array because that should cover us most of the time.
            self.serializedBytes = []
            self.serializedBytes.reserveCapacity(1024)
        }

        /// Appends a single, non-constructed node to the content.
        mutating func appendPrimitiveNode(identifier: ASN1.ASN1Identifier, _ contentWriter: (inout [UInt8]) throws -> Void) rethrows {
            assert(identifier.primitive)
            try self._appendNode(identifier: identifier) { try contentWriter(&$0.serializedBytes) }
        }

        mutating func appendConstructedNode(identifier: ASN1.ASN1Identifier, _ contentWriter: (inout Serializer) throws -> Void) rethrows {
            assert(identifier.constructed)
            try self._appendNode(identifier: identifier, contentWriter)
        }

        mutating func serialize<T: ASN1Serializable>(_ node: T) throws {
            try node.serialize(into: &self)
        }

        mutating func serialize<T: ASN1Serializable>(_ node: T, explicitlyTaggedWithTagNumber tagNumber: Int, tagClass: ASN1.ASN1Identifier.TagClass) throws {
            let identifier = ASN1Identifier(explicitTagWithNumber: tagNumber, tagClass: tagClass)
            try self.appendConstructedNode(identifier: identifier) { coder in
                try coder.serialize(node)
            }
        }

        // This is the base logical function that all other append methods are built on. This one has most of the logic, and doesn't
        // police what we expect to happen in the content writer.
        private mutating func _appendNode(identifier: ASN1.ASN1Identifier, _ contentWriter: (inout Serializer) throws -> Void) rethrows {
            // This is a tricky game to play. We want to write the identifier and the length, but we don't know what the
            // length is here. To get around that, we _assume_ the length will be one byte, and let the writer write their content.
            // If it turns out to have been longer, we recalculate how many bytes we need and shuffle them in the buffer,
            // before updating the length. Most of the time we'll be right: occasionally we'll be wrong and have to shuffle.
            self.serializedBytes.writeIdentifier(identifier)

            // Write a zero for the length.
            self.serializedBytes.append(0)

            // Save the indices and write.
            let originalEndIndex = self.serializedBytes.endIndex
            let lengthIndex = self.serializedBytes.index(before: originalEndIndex)

            try contentWriter(&self)

            let contentLength = self.serializedBytes.distance(from: originalEndIndex, to: self.serializedBytes.endIndex)
            let lengthBytesNeeded = contentLength.bytesNeededToEncode
            if lengthBytesNeeded == 1 {
                // We can just set this at the top, and we're done!
                assert(contentLength <= 0x7F)
                self.serializedBytes[lengthIndex] = UInt8(contentLength)
                return
            }

            // Whoops, we need more than one byte to represent the length. That's annoying!
            // To sort this out we want to "move" the memory to the right.
            self.serializedBytes.moveRange(offset: lengthBytesNeeded - 1, range: originalEndIndex..<self.serializedBytes.endIndex)

            // Now we can write the length bytes back. We first write the number of length bytes
            // we needed, setting the high bit. Then we write the bytes of the length.
            self.serializedBytes[lengthIndex] = 0x80 | UInt8(lengthBytesNeeded - 1)
            var writeIndex = lengthIndex

            for shift in (0..<(lengthBytesNeeded - 1)).reversed() {
                // Shift and mask the integer.
                self.serializedBytes.formIndex(after: &writeIndex)
                self.serializedBytes[writeIndex] = UInt8((contentLength >> (shift * 8)) | 0x80 )
            }

            assert(writeIndex == self.serializedBytes.index(lengthIndex, offsetBy: lengthBytesNeeded - 1))
        }
    }
}

// MARK: - Helpers
internal protocol ASN1Parseable {
    init(asn1Encoded: ASN1.ASN1Node) throws
}

extension ASN1Parseable {
    internal init(asn1Encoded sequenceNodeIterator: inout ASN1.ASN1NodeCollection.Iterator) throws {
        guard let node = sequenceNodeIterator.next() else {
            throw CryptoKitASN1Error.invalidASN1Object
        }

        self = try .init(asn1Encoded: node)
    }

    internal init(asn1Encoded: [UInt8]) throws {
        self = try .init(asn1Encoded: ASN1.parse(asn1Encoded))
    }
}

internal protocol ASN1Serializable {
    func serialize(into coder: inout ASN1.Serializer) throws
}

extension ArraySlice where Element == UInt8 {
    fileprivate mutating func readASN1Length() throws -> UInt? {
        guard let firstByte = self.popFirst() else {
            return nil
        }

        switch firstByte {
        case 0x80:
            // Indefinite form. Unsupported.
            throw CryptoKitASN1Error.unsupportedFieldLength
        case let val where val & 0x80 == 0x80:
            // Top bit is set, this is the long form. The remaining 7 bits of this octet
            // determine how long the length field is.
            let fieldLength = Int(val & 0x7F)
            guard self.count >= fieldLength else {
                return nil
            }

            // We need to read the length bytes
            let lengthBytes = self.prefix(fieldLength)
            self = self.dropFirst(fieldLength)
            let length = try UInt(bigEndianBytes: lengthBytes)

            // DER requires that we enforce that the length field was encoded in the minimum number of octets necessary.
            let requiredBits = UInt.bitWidth - length.leadingZeroBitCount
            switch requiredBits {
            case 0...7:
                // For 0 to 7 bits, the long form is unnacceptable and we require the short.
                throw CryptoKitASN1Error.unsupportedFieldLength
            case 8...:
                // For 8 or more bits, fieldLength should be the minimum required.
                let requiredBytes = (requiredBits + 7) / 8
                if fieldLength > requiredBytes {
                    throw CryptoKitASN1Error.unsupportedFieldLength
                }
            default:
                // This is not reachable, but we'll error anyway.
                throw CryptoKitASN1Error.unsupportedFieldLength
            }

            return length
        case let val:
            // Short form, the length is only one 7-bit integer.
            return UInt(val)
        }
    }
}

extension FixedWidthInteger {
    internal init<Bytes: Collection>(bigEndianBytes bytes: Bytes) throws where Bytes.Element == UInt8 {
        guard bytes.count <= (Self.bitWidth / 8) else {
            throw CryptoKitASN1Error.invalidASN1Object
        }

        self = 0
        let shiftSizes = stride(from: 0, to: bytes.count * 8, by: 8).reversed()

        var index = bytes.startIndex
        for shift in shiftSizes {
            self |= Self(truncatingIfNeeded: bytes[index]) << shift
            bytes.formIndex(after: &index)
        }
    }
}

extension Array where Element == UInt8 {
    fileprivate mutating func writeIdentifier(_ identifier: ASN1.ASN1Identifier) {
        self.append(identifier.baseTag)
    }

    fileprivate mutating func moveRange(offset: Int, range: Range<Index>) {
        // We only bothered to implement this for positive offsets for now, the algorithm
        // generalises.
        precondition(offset > 0)

        let distanceFromEndOfRangeToEndOfSelf = self.distance(from: range.endIndex, to: self.endIndex)
        if distanceFromEndOfRangeToEndOfSelf < offset {
            // We begin by writing some zeroes out to the size we need.
            for _ in 0..<(offset - distanceFromEndOfRangeToEndOfSelf) {
                self.append(0)
            }
        }

        // Now we walk the range backwards, moving the elements.
        for index in range.reversed() {
            self[index + offset] = self[index]
        }
    }
}

extension Int {
    fileprivate var bytesNeededToEncode: Int {
        // ASN.1 lengths are in two forms. If we can store the length in 7 bits, we should:
        // that requires only one byte. Otherwise, we need multiple bytes: work out how many,
        // plus one for the length of the length bytes.
        if self <= 0x7F {
            return 1
        } else {
            // We need to work out how many bytes we need. There are many fancy bit-twiddling
            // ways of doing this, but honestly we don't do this enough to need them, so we'll
            // do it the easy way. This math is done on UInt because it makes the shift semantics clean.
            // We save a branch here because we can never overflow this addition.
            return UInt(self).neededBytes &+ 1
        }
    }
}

extension FixedWidthInteger {
    // Bytes needed to store a given integer.
    internal var neededBytes: Int {
        let neededBits = self.bitWidth - self.leadingZeroBitCount
        return (neededBits + 7) / 8
    }
}

#endif // Linux or !SwiftPM
