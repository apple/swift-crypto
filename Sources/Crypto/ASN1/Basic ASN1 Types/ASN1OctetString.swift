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

extension ASN1 {
    /// An octet string is a representation of a string of octets.
    struct ASN1OctetString: ASN1ImplicitlyTaggable {
        static var defaultIdentifier: ASN1.ASN1Identifier {
            .primitiveOctetString
        }

        var bytes: ArraySlice<UInt8>

        init(asn1Encoded node: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws(CryptoKitMetaError) {
            guard node.identifier == identifier else {
                throw error(CryptoKitASN1Error.unexpectedFieldType)
            }

            guard case .primitive(let content) = node.content else {
                preconditionFailure("ASN.1 parser generated primitive node with constructed content")
            }

            self.bytes = content
        }

        init(contentBytes: ArraySlice<UInt8>) {
            self.bytes = contentBytes
        }

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws(CryptoKitMetaError) {
            try coder.appendPrimitiveNode(identifier: identifier) { bytes in
                bytes.append(contentsOf: self.bytes)
            }
        }
    }
}

extension ASN1.ASN1OctetString: Hashable { }

extension ASN1.ASN1OctetString: ContiguousBytes {
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

#endif // canImport(CryptoKit)
