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
    struct PBES2Parameters: DERImplicitlyTaggable {
        static var defaultIdentifier: SwiftASN1.ASN1Identifier { .sequence }
        
        let keyDerivationFunction: KeyDerivationFunction
        let encryptionScheme: EncryptionScheme
        
        init(keyDerivationFunction: KeyDerivationFunction, encryptionScheme: EncryptionScheme) {
            self.keyDerivationFunction = keyDerivationFunction
            self.encryptionScheme = encryptionScheme
        }
        
        init(derEncoded: SwiftASN1.ASN1Node, withIdentifier identifier: SwiftASN1.ASN1Identifier) throws {
            self = try DER.sequence(derEncoded, identifier: identifier) { nodes in
                let keyDerivationFunction = try KeyDerivationFunction(derEncoded: &nodes)
                let encryptionScheme = try EncryptionScheme(derEncoded: &nodes)
                
                return .init(keyDerivationFunction: keyDerivationFunction, encryptionScheme: encryptionScheme)
            }
        }
        
        func serialize(into coder: inout SwiftASN1.DER.Serializer, withIdentifier identifier: SwiftASN1.ASN1Identifier) throws {
            try coder.appendConstructedNode(identifier: identifier) { coder in
                try self.keyDerivationFunction.serialize(into: &coder)
                try self.encryptionScheme.serialize(into: &coder)
            }
        }
    }
}
