//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import SwiftASN1

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ASN1 {
    // A PKCS#8 private key is one of two formats, depending on the version:
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
    // We disregard the attributes because we don't support them anyway.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    struct PKCS8PrivateKey: DERImplicitlyTaggable {
        static var defaultIdentifier: ASN1Identifier {
            .sequence
        }

        var algorithm: RFC8410AlgorithmIdentifier

        var privateKey: ASN1OctetString

        init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
            self = try DER.sequence(rootNode, identifier: identifier) { nodes in
                let version = try Int(derEncoded: &nodes)
                guard version == 0 || version == 1 else {
                    throw ASN1Error.invalidASN1Object(reason: "Version number mismatch")
                }

                let algorithm = try ASN1.RFC8410AlgorithmIdentifier(derEncoded: &nodes)
                let privateKeyBytes = try ASN1OctetString(derEncoded: &nodes)

                // We ignore the attributes
                _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { _ in }

                let privateKeyNode = try DER.parse(privateKeyBytes.bytes)
                let privateKey = try ASN1OctetString(derEncoded: privateKeyNode)

                return try .init(algorithm: algorithm, privateKey: privateKey)
            }
        }

        private init(algorithm: ASN1.RFC8410AlgorithmIdentifier, privateKey: ASN1OctetString) throws {
            self.privateKey = privateKey
            self.algorithm = algorithm
        }

        init(algorithm: ASN1.RFC8410AlgorithmIdentifier, privateKey: [UInt8]) {
            self.algorithm = algorithm
            self.privateKey = ASN1OctetString(contentBytes: privateKey[...])
        }

        func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
            try coder.appendConstructedNode(identifier: identifier) { coder in
                try coder.serialize(0)
                try coder.serialize(self.algorithm)

                // Here's a weird one: we recursively serialize the private key, and then turn the bytes into an octet string.
                var subCoder = DER.Serializer()
                try subCoder.serialize(self.privateKey)
                let serializedKey = ASN1OctetString(contentBytes: subCoder.serializedBytes[...])

                try coder.serialize(serializedKey)
            }
        }
    }
}
