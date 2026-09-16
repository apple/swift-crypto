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

#if canImport(CryptoKit)
@_exported import CryptoKit
#else

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

private func contents(of string: StaticString) -> ArraySlice<UInt8> {
    if string.hasPointerRepresentation {
        return ArraySlice(
            UnsafeBufferPointer(start: string.utf8Start, count: string.utf8CodeUnitCount)
        )
    } else {
        return string.withUTF8Buffer { ptr in
            // Here ptr points to a word-sized temporary value that holds the
            // UTF-8 representation of the single Unicode codepoint held in `string`.
            // We need to copy this because it's only valid inside the closure.
            ArraySlice(Array(ptr))
        }
    }
}

extension ASN1 {
    /// A UTF8String is roughly what it sounds like. We note that all the string types are encoded as implicitly tagged
    /// octet strings, and so for now we just piggyback on the decoder and encoder for that type.
    struct ASN1UTF8String: ASN1ImplicitlyTaggable, Hashable, ContiguousBytes {
        static var defaultIdentifier: ASN1.ASN1Identifier {
            .primitiveUTF8String
        }

        var bytes: ArraySlice<UInt8>

        init(asn1Encoded node: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws(CryptoKitMetaError) {
            self.bytes = try ASN1OctetString(asn1Encoded: node, withIdentifier: identifier).bytes
        }

        init(contentBytes: ArraySlice<UInt8>) {
            self.bytes = contentBytes
        }

#if hasFeature(Embedded)
        init(_ string: StaticString) {
            self.bytes = contents(of: string)
        }
#else
        init(_ string: String) {
            self.bytes = ArraySlice(string.utf8)
        }
#endif

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws(CryptoKitMetaError) {
            let octet = ASN1OctetString(contentBytes: self.bytes)
            try octet.serialize(into: &coder, withIdentifier: identifier)
        }

        #if hasFeature(Embedded)
        func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
        #else
        func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
        #endif
    }

    /// We note that all the string types are encoded as implicitly tagged
    /// octet strings, and so for now we just piggyback on the decoder and encoder for that type.
    struct ASN1TeletexString: ASN1ImplicitlyTaggable, Hashable, ContiguousBytes {
        static var defaultIdentifier: ASN1.ASN1Identifier {
            .primitiveTeletexString
        }

        var bytes: ArraySlice<UInt8>

        init(asn1Encoded node: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws(CryptoKitMetaError) {
            self.bytes = try ASN1OctetString(asn1Encoded: node, withIdentifier: identifier).bytes
        }

        init(contentBytes: ArraySlice<UInt8>) {
            self.bytes = contentBytes
        }

#if hasFeature(Embedded)
        init(_ string: StaticString) {
            self.bytes = contents(of: string)
        }
#else
        init(_ string: String) {
            self.bytes = ArraySlice(string.utf8)
        }
#endif

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws(CryptoKitMetaError) {
            let octet = ASN1OctetString(contentBytes: self.bytes)
            try octet.serialize(into: &coder, withIdentifier: identifier)
        }

        #if hasFeature(Embedded)
        func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
        #else
        func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
        #endif
    }

    /// We note that all the string types are encoded as implicitly tagged
    /// octet strings, and so for now we just piggyback on the decoder and encoder for that type.
    struct ASN1PrintableString: ASN1ImplicitlyTaggable, Hashable, ContiguousBytes {
        static var defaultIdentifier: ASN1.ASN1Identifier {
            .primitivePrintableString
        }

        var bytes: ArraySlice<UInt8>

        init(asn1Encoded node: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws(CryptoKitMetaError) {
            self.bytes = try ASN1OctetString(asn1Encoded: node, withIdentifier: identifier).bytes
        }

        init(contentBytes: ArraySlice<UInt8>) {
            self.bytes = contentBytes
        }

#if hasFeature(Embedded)
        init(_ string: StaticString) {
            self.bytes = contents(of: string)
        }
#else
        init(_ string: String) {
            self.bytes = ArraySlice(string.utf8)
        }
#endif

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws(CryptoKitMetaError) {
            let octet = ASN1OctetString(contentBytes: self.bytes)
            try octet.serialize(into: &coder, withIdentifier: identifier)
        }

        #if hasFeature(Embedded)
        func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
        #else
        func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
        #endif
    }

    /// We note that all the string types are encoded as implicitly tagged
    /// octet strings, and so for now we just piggyback on the decoder and encoder for that type.
    struct ASN1UniversalString: ASN1ImplicitlyTaggable, Hashable, ContiguousBytes {
        static var defaultIdentifier: ASN1.ASN1Identifier {
            .primitiveUniversalString
        }

        var bytes: ArraySlice<UInt8>

        init(asn1Encoded node: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws(CryptoKitMetaError) {
            self.bytes = try ASN1OctetString(asn1Encoded: node, withIdentifier: identifier).bytes
        }

        init(contentBytes: ArraySlice<UInt8>) {
            self.bytes = contentBytes
        }

#if hasFeature(Embedded)
        init(_ string: StaticString) {
            self.bytes = contents(of: string)
        }
#else
        init(_ string: String) {
            self.bytes = ArraySlice(string.utf8)
        }
#endif

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws(CryptoKitMetaError) {
            let octet = ASN1OctetString(contentBytes: self.bytes)
            try octet.serialize(into: &coder, withIdentifier: identifier)
        }

        #if hasFeature(Embedded)
        func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
        #else
        func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
        #endif
    }

    /// We note that all the string types are encoded as implicitly tagged
    /// octet strings, and so for now we just piggyback on the decoder and encoder for that type.
    struct ASN1BMPString: ASN1ImplicitlyTaggable, Hashable, ContiguousBytes {
        static var defaultIdentifier: ASN1.ASN1Identifier {
            .primitiveBMPString
        }

        var bytes: ArraySlice<UInt8>

        init(asn1Encoded node: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws(CryptoKitMetaError) {
            self.bytes = try ASN1OctetString(asn1Encoded: node, withIdentifier: identifier).bytes
        }

        init(contentBytes: ArraySlice<UInt8>) {
            self.bytes = contentBytes
        }

#if hasFeature(Embedded)
        init(_ string: StaticString) {
            self.bytes = contents(of: string)
        }
#else
        init(_ string: String) {
            self.bytes = ArraySlice(string.utf8)
        }
#endif

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws(CryptoKitMetaError) {
            let octet = ASN1OctetString(contentBytes: self.bytes)
            try octet.serialize(into: &coder, withIdentifier: identifier)
        }

        #if hasFeature(Embedded)
        func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
        #else
        func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
        #endif
    }
}

#if !hasFeature(Embedded)
extension ASN1.ASN1TeletexString: ExpressibleByStringLiteral {
    public init(stringLiteral value: StringLiteralType) {
        self.bytes = ArraySlice(value.utf8)
    }
}

extension ASN1.ASN1UTF8String: ExpressibleByStringLiteral {
    public init(stringLiteral value: StringLiteralType) {
        self.bytes = ArraySlice(value.utf8)
    }
}

extension ASN1.ASN1PrintableString: ExpressibleByStringLiteral {
    public init(stringLiteral value: StringLiteralType) {
        self.bytes = ArraySlice(value.utf8)
    }
}

extension ASN1.ASN1UniversalString: ExpressibleByStringLiteral {
    public init(stringLiteral value: StringLiteralType) {
        self.bytes = ArraySlice(value.utf8)
    }
}

extension ASN1.ASN1BMPString: ExpressibleByStringLiteral {
    public init(stringLiteral value: StringLiteralType) {
        self.bytes = ArraySlice(value.utf8)
    }
}
#endif


#endif // canImport(CryptoKit)
