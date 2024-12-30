//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SwiftASN1

extension EncryptedPEMDocument {
    struct EncryptionScheme: DERImplicitlyTaggable {
        static var defaultIdentifier: SwiftASN1.ASN1Identifier { .sequence }
        
        let encryptionAlgorithm: ASN1ObjectIdentifier
        let encryptionAlgorithmParameters: ASN1OctetString
        
        init(encryptionAlgorithm: ASN1ObjectIdentifier, encryptionAlgorithmParameters: ASN1OctetString) {
            self.encryptionAlgorithm = encryptionAlgorithm
            self.encryptionAlgorithmParameters = encryptionAlgorithmParameters
        }
        
        init(derEncoded: SwiftASN1.ASN1Node, withIdentifier identifier: SwiftASN1.ASN1Identifier) throws {
            self = try DER.sequence(derEncoded, identifier: identifier) { nodes in
                let encryptionAlgorithm = try ASN1ObjectIdentifier(derEncoded: &nodes)
                let encryptionAlgorithmParameters = try ASN1OctetString(derEncoded: &nodes)
                
                return .init(encryptionAlgorithm: encryptionAlgorithm, encryptionAlgorithmParameters: encryptionAlgorithmParameters)
            }
        }
        
        func serialize(into coder: inout SwiftASN1.DER.Serializer, withIdentifier identifier: SwiftASN1.ASN1Identifier) throws {
            try coder.appendConstructedNode(identifier: identifier) { coder in
                try self.encryptionAlgorithm.serialize(into: &coder)
                try self.encryptionAlgorithmParameters.serialize(into: &coder)
            }
        }
    }
}

