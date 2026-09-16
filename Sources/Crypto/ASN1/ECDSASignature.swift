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
    /// An ECDSA signature is laid out as follows:
    ///
    /// ECDSASignature ::= SEQUENCE {
    ///   r INTEGER,
    ///   s INTEGER
    /// }
    ///
    /// This type is generic because our different backends want to use different bignum representations.
    struct ECDSASignature<IntegerType: ASN1IntegerRepresentable>: ASN1ImplicitlyTaggable {
        static var defaultIdentifier: ASN1.ASN1Identifier {
            .sequence
        }

        var r: IntegerType
        var s: IntegerType

        init(r: IntegerType, s: IntegerType) {
            self.r = r
            self.s = s
        }

        init(asn1Encoded rootNode: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws(CryptoKitMetaError) {
            self = try ASN1.sequence(rootNode, identifier: identifier) { nodes throws(CryptoKitMetaError) in
                let r = try IntegerType(asn1Encoded: &nodes)
                let s = try IntegerType(asn1Encoded: &nodes)

                return ECDSASignature(r: r, s: s)
            }
        }

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws(CryptoKitMetaError) {
            try coder.appendConstructedNode(identifier: identifier) { coder throws(CryptoKitMetaError) in
                try coder.serialize(self.r)
                try coder.serialize(self.s)
            }
        }
    }
}

#endif // canImport(CryptoKit)
