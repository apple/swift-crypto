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

        init(asn1Encoded rootNode: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            self = try ASN1.sequence(rootNode, identifier: identifier) { nodes in
                let r = try IntegerType(asn1Encoded: &nodes)
                let s = try IntegerType(asn1Encoded: &nodes)

                return ECDSASignature(r: r, s: s)
            }
        }

        func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            try coder.appendConstructedNode(identifier: identifier) { coder in
                try coder.serialize(self.r)
                try coder.serialize(self.s)
            }
        }
    }
}

#endif // Linux or !SwiftPM
