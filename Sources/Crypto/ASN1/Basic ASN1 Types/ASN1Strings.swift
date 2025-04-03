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
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
import Foundation

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ASN1 {
    /// A UTF8String is roughly what it sounds like. We note that all the string types are encoded as implicitly tagged
    /// octet strings, and so for now we just piggyback on the decoder and encoder for that type.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    struct ASN1UTF8String: ASN1ImplicitlyTaggable, Hashable, ContiguousBytes, ExpressibleByStringLiteral {
        static var defaultIdentifier: ASN1.ASN1Identifier {
            .primitiveUTF8String
        }

        var bytes: ArraySlice<UInt8>

        init(asn1Encoded node: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            self.bytes = try ASN1OctetString(asn1Encoded: node, withIdentifier: identifier).bytes
        }

        init(contentBytes: ArraySlice<UInt8>) {
            self.bytes = contentBytes
        }

        init(stringLiteral value: StringLiteralType) {
            self.bytes = ArraySlice(value.utf8)
        }

        init(_ string: String) {
            self.bytes = ArraySlice(string.utf8)
        }

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            let octet = ASN1OctetString(contentBytes: self.bytes)
            try octet.serialize(into: &coder, withIdentifier: identifier)
        }

        func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
    }

    /// We note that all the string types are encoded as implicitly tagged
    /// octet strings, and so for now we just piggyback on the decoder and encoder for that type.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    struct ASN1TeletexString: ASN1ImplicitlyTaggable, Hashable, ContiguousBytes, ExpressibleByStringLiteral {
        static var defaultIdentifier: ASN1.ASN1Identifier {
            .primitiveTeletexString
        }

        var bytes: ArraySlice<UInt8>

        init(asn1Encoded node: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            self.bytes = try ASN1OctetString(asn1Encoded: node, withIdentifier: identifier).bytes
        }

        init(contentBytes: ArraySlice<UInt8>) {
            self.bytes = contentBytes
        }

        init(stringLiteral value: StringLiteralType) {
            self.bytes = ArraySlice(value.utf8)
        }

        init(_ string: String) {
            self.bytes = ArraySlice(string.utf8)
        }

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            let octet = ASN1OctetString(contentBytes: self.bytes)
            try octet.serialize(into: &coder, withIdentifier: identifier)
        }

        func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
    }

    /// We note that all the string types are encoded as implicitly tagged
    /// octet strings, and so for now we just piggyback on the decoder and encoder for that type.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    struct ASN1PrintableString: ASN1ImplicitlyTaggable, Hashable, ContiguousBytes, ExpressibleByStringLiteral {
        static var defaultIdentifier: ASN1.ASN1Identifier {
            .primitivePrintableString
        }

        var bytes: ArraySlice<UInt8>

        init(asn1Encoded node: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            self.bytes = try ASN1OctetString(asn1Encoded: node, withIdentifier: identifier).bytes
        }

        init(contentBytes: ArraySlice<UInt8>) {
            self.bytes = contentBytes
        }

        init(stringLiteral value: StringLiteralType) {
            self.bytes = ArraySlice(value.utf8)
        }

        init(_ string: String) {
            self.bytes = ArraySlice(string.utf8)
        }

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            let octet = ASN1OctetString(contentBytes: self.bytes)
            try octet.serialize(into: &coder, withIdentifier: identifier)
        }

        func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
    }

    /// We note that all the string types are encoded as implicitly tagged
    /// octet strings, and so for now we just piggyback on the decoder and encoder for that type.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    struct ASN1UniversalString: ASN1ImplicitlyTaggable, Hashable, ContiguousBytes, ExpressibleByStringLiteral {
        static var defaultIdentifier: ASN1.ASN1Identifier {
            .primitiveUniversalString
        }

        var bytes: ArraySlice<UInt8>

        init(asn1Encoded node: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            self.bytes = try ASN1OctetString(asn1Encoded: node, withIdentifier: identifier).bytes
        }

        init(contentBytes: ArraySlice<UInt8>) {
            self.bytes = contentBytes
        }

        init(stringLiteral value: StringLiteralType) {
            self.bytes = ArraySlice(value.utf8)
        }

        init(_ string: String) {
            self.bytes = ArraySlice(string.utf8)
        }

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            let octet = ASN1OctetString(contentBytes: self.bytes)
            try octet.serialize(into: &coder, withIdentifier: identifier)
        }

        func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
    }

    /// We note that all the string types are encoded as implicitly tagged
    /// octet strings, and so for now we just piggyback on the decoder and encoder for that type.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    struct ASN1BMPString: ASN1ImplicitlyTaggable, Hashable, ContiguousBytes, ExpressibleByStringLiteral {
        static var defaultIdentifier: ASN1.ASN1Identifier {
            .primitiveBMPString
        }

        var bytes: ArraySlice<UInt8>

        init(asn1Encoded node: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            self.bytes = try ASN1OctetString(asn1Encoded: node, withIdentifier: identifier).bytes
        }

        init(contentBytes: ArraySlice<UInt8>) {
            self.bytes = contentBytes
        }

        init(stringLiteral value: StringLiteralType) {
            self.bytes = ArraySlice(value.utf8)
        }

        init(_ string: String) {
            self.bytes = ArraySlice(string.utf8)
        }

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            let octet = ASN1OctetString(contentBytes: self.bytes)
            try octet.serialize(into: &coder, withIdentifier: identifier)
        }

        func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            return try self.bytes.withUnsafeBytes(body)
        }
    }
}

#endif // Linux or !SwiftPM
