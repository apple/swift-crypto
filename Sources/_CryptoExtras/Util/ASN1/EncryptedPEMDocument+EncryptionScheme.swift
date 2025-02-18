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
    struct EncryptionScheme: DERParseable {
        static var defaultIdentifier: SwiftASN1.ASN1Identifier { .sequence }
        
        let encryptionAlgorithm: ASN1ObjectIdentifier
        let encryptionAlgorithmParameters: ASN1OctetString
        
        init(encryptionAlgorithm: ASN1ObjectIdentifier, encryptionAlgorithmParameters: ASN1OctetString) {
            self.encryptionAlgorithm = encryptionAlgorithm
            self.encryptionAlgorithmParameters = encryptionAlgorithmParameters
        }
        
        init(derEncoded node: ASN1Node) throws {
            self = try DER.sequence(node, identifier: .sequence) { nodes in
                let encryptionAlgorithm = try ASN1ObjectIdentifier(derEncoded: &nodes)
                let encryptionAlgorithmParameters = try ASN1OctetString(derEncoded: &nodes)
                
                return .init(encryptionAlgorithm: encryptionAlgorithm, encryptionAlgorithmParameters: encryptionAlgorithmParameters)
            }
        }
    }
}

