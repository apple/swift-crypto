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
    //
    // The private key octet string contains (surprise!) a SEC1-encoded private key! So we recursively invoke the
    // ASN.1 parser and go again.
    struct PKCS8PrivateKey: ASN1Parseable, ASN1Serializable {
        var algorithm: RFC5480AlgorithmIdentifier

        var privateKey: ASN1.SEC1PrivateKey

        init(asn1Encoded rootNode: ASN1.ASN1Node) throws {
            self = try ASN1.sequence(rootNode) { nodes in
                let version = try Int(asn1Encoded: &nodes)
                guard version == 0 else {
                    throw CryptoKitASN1Error.invalidASN1Object
                }

                let algorithm = try ASN1.RFC5480AlgorithmIdentifier(asn1Encoded: &nodes)
                let privateKeyBytes = try ASN1.ASN1OctetString(asn1Encoded: &nodes)

                // We ignore the attributes
                _ = try ASN1.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { _ in }

                let sec1PrivateKeyNode = try ASN1.parse(privateKeyBytes.bytes)
                let sec1PrivateKey = try ASN1.SEC1PrivateKey(asn1Encoded: sec1PrivateKeyNode)
                if let innerAlgorithm = sec1PrivateKey.algorithm, innerAlgorithm != algorithm {
                    throw CryptoKitASN1Error.invalidASN1Object
                }

                return try .init(algorithm: algorithm, privateKey: sec1PrivateKey)
            }
        }

        private init(algorithm: ASN1.RFC5480AlgorithmIdentifier, privateKey: ASN1.SEC1PrivateKey) throws {
            self.privateKey = privateKey
            self.algorithm = algorithm
        }

        init(algorithm: ASN1.RFC5480AlgorithmIdentifier, privateKey: [UInt8], publicKey: [UInt8]) {
            self.algorithm = algorithm

            // We nil out the private key here. I don't really know why we do this, but OpenSSL does, and it seems
            // safe enough to do: it certainly avoids the possibility of disagreeing on what it is!
            self.privateKey = ASN1.SEC1PrivateKey(privateKey: privateKey, algorithm: nil, publicKey: publicKey)
        }

        func serialize(into coder: inout ASN1.Serializer) throws {
            try coder.appendConstructedNode(identifier: .sequence) { coder in
                try coder.serialize(0)  // version
                try coder.serialize(self.algorithm)

                // Here's a weird one: we recursively serialize the private key, and then turn the bytes into an octet string.
                var subCoder = ASN1.Serializer()
                try subCoder.serialize(self.privateKey)
                let serializedKey = ASN1.ASN1OctetString(contentBytes: subCoder.serializedBytes[...])

                try coder.serialize(serializedKey)
            }
        }
    }
}

#endif // Linux or !SwiftPM
