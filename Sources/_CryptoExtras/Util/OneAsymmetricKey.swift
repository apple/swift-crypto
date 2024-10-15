//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SwiftASN1

// For private keys, RFC 5958 uses:
//
// OneAsymmetricKey ::= SEQUENCE {
//    version Version,
//    privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
//    privateKey PrivateKey,
//    attributes [0] IMPLICIT Attributes OPTIONAL,
//    ...,
//    [[2: publicKey [1] IMPLICIT PublicKey OPTIONAL ]],
//    ...
// }
//
// PrivateKey ::= OCTET STRING
//
// PublicKey ::= BIT STRING
struct OneAsymmetricKey: DERImplicitlyTaggable, PEMRepresentable {
    static let defaultPEMDiscriminator: String = "PRIVATE KEY"

    static var defaultIdentifier: ASN1Identifier {
        return .sequence
    }

    var algorithm: RFC5480AlgorithmIdentifier

    var privateKey: ASN1OctetString

    var attributes: ASN1Any?

    var publicKey: ASN1BitString?

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let _ = try Int(derEncoded: &nodes) // version
            let algorithmIdentifier = try RFC5480AlgorithmIdentifier(derEncoded: &nodes)
            let privateKey = try ASN1OctetString(derEncoded: &nodes)

            let attributes = DER.optionalImplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { node in
                return ASN1Any(derEncoded: node)
            }

            let publicKey = try DER.optionalImplicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) { node in
                return try ASN1BitString(derEncoded: node)
            }

            return try .init(algorithm: algorithmIdentifier.algorithm, privateKey: privateKey, attributes: attributes, publicKey: publicKey)
        }
    }

    private init(
        algorithm: ASN1ObjectIdentifier,
        privateKey: ASN1OctetString,
        attributes: ASN1Any?,
        publicKey: ASN1BitString?
    ) throws {
        self.algorithm = RFC5480AlgorithmIdentifier(algorithm: algorithm, parameters: nil)
        self.privateKey = privateKey
        self.attributes = attributes
        self.publicKey = publicKey
    }

    init(
        algorithm: RFC5480AlgorithmIdentifier,
        privateKey: [UInt8],
        attributes: ASN1Any? = nil,
        publicKey: [UInt8]? = nil
    ) {
        self.algorithm = algorithm
        self.privateKey = ASN1OctetString(contentBytes: privateKey[...])
        self.attributes = attributes
        self.publicKey = if let publicKey { ASN1BitString(bytes: publicKey[...]) } else { nil }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(0)  // version
            try coder.serialize(algorithm)
            try coder.serialize(self.privateKey)
            
            /* error: Instance method 'serializeOptionalImplicitlyTagged(_:withIdentifier:)' requires that 'ASN1Any' conform to 'DERImplicitlyTaggable'
            if let attributes = self.attributes {
                try coder.serializeOptionalImplicitlyTagged(attributes, withIdentifier: .init(tagWithNumber: 0, tagClass: .contextSpecific))
            }
            */
            
            if let publicKey = self.publicKey {
                try coder.serializeOptionalImplicitlyTagged(publicKey, withIdentifier: .init(tagWithNumber: 1, tagClass: .contextSpecific))
            }
        }
    }
}