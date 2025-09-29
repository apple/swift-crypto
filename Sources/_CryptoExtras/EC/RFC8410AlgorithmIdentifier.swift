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

import SwiftASN1

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ASN1 {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    struct RFC8410AlgorithmIdentifier: DERImplicitlyTaggable, Hashable {
        static var defaultIdentifier: ASN1Identifier {
            .sequence
        }

        var algorithm: ASN1ObjectIdentifier

        // RFC 8410: For all of these OIDs, the parameters MUST be absent.
        // They are still part of the identifer block.
        var parameters: ASN1Any?

        init(algorithm: ASN1ObjectIdentifier, parameters: ASN1Any?) {
            self.algorithm = algorithm
            self.parameters = parameters
        }

        init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
            // The AlgorithmIdentifier block looks like this.
            //
            // AlgorithmIdentifier  ::=  SEQUENCE  {
            //   algorithm   OBJECT IDENTIFIER,
            //   parameters  ANY DEFINED BY algorithm OPTIONAL
            // }
            //
            // We don't bother with helpers: we just try to decode it directly.
            self = try DER.sequence(rootNode, identifier: identifier) { nodes in
                let algorithmOID = try ASN1ObjectIdentifier(berEncoded: &nodes)

                let parameters = nodes.next().map { ASN1Any(berEncoded: $0) }

                return .init(algorithm: algorithmOID, parameters: parameters)
            }
        }

        func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
            try coder.appendConstructedNode(identifier: identifier) { coder in
                try coder.serialize(self.algorithm)
                if let parameters = self.parameters {
                    try coder.serialize(parameters)
                }
            }
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ASN1.RFC8410AlgorithmIdentifier {
    static let x25519 = ASN1.RFC8410AlgorithmIdentifier(algorithm: .AlgorithmIdentifier.idX25519, parameters: nil)

    static let x448 = ASN1.RFC8410AlgorithmIdentifier(algorithm: .AlgorithmIdentifier.idX448, parameters: nil)

    static let ed25519 = ASN1.RFC8410AlgorithmIdentifier(algorithm: .AlgorithmIdentifier.idEd25519, parameters: nil)

    static let ed448 = ASN1.RFC8410AlgorithmIdentifier(algorithm: .AlgorithmIdentifier.idEd448, parameters: nil)
}
