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

extension ASN1 {
    /// An ASN1 ANY represents...well, anything.
    ///
    /// In this case we store the ASN.1 ANY as a serialized representation. This is a bit annoying,
    /// but it's the only safe way to manage this data, as we cannot arbitrarily parse it.
    ///
    /// The only things we allow users to do with ASN.1 ANYs is to try to decode them as something else,
    /// to create them from something else, or to serialize them.
    struct ASN1Any: ASN1Parseable, ASN1Serializable, Hashable {
        fileprivate var serializedBytes: ArraySlice<UInt8>

        init<ASN1Type: ASN1Serializable>(erasing: ASN1Type) throws {
            var serializer = ASN1.Serializer()
            try erasing.serialize(into: &serializer)
            self.serializedBytes = ArraySlice(serializer.serializedBytes)
        }

        init<ASN1Type: ASN1ImplicitlyTaggable>(erasing: ASN1Type, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            var serializer = ASN1.Serializer()
            try erasing.serialize(into: &serializer, withIdentifier: identifier)
            self.serializedBytes = ArraySlice(serializer.serializedBytes)
        }

        init(asn1Encoded rootNode: ASN1.ASN1Node) {
            // This is a bit sad: we just re-serialize this data. In an ideal world
            // we'd update the parse representation so that all nodes can point at their
            // complete backing storage, but for now this is better.
            var serializer = ASN1.Serializer()
            serializer.serialize(rootNode)
            self.serializedBytes = ArraySlice(serializer.serializedBytes)
        }

        func serialize(into coder: inout ASN1.Serializer) throws {
            // Dangerous to just reach in there like this, but it's the right way to serialize this.
            coder.serializedBytes.append(contentsOf: self.serializedBytes)
        }
    }
}

extension ASN1Parseable {
    init(asn1Any: ASN1.ASN1Any) throws {
        try self.init(asn1Encoded: asn1Any.serializedBytes)
    }
}

extension ASN1ImplicitlyTaggable {
    init(asn1Any: ASN1.ASN1Any, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        try self.init(asn1Encoded: asn1Any.serializedBytes, withIdentifier: identifier)
    }
}

#endif // Linux or !SwiftPM
