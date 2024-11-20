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
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
import Foundation

extension HPKE {
    struct Context {
        var keySchedule: KeySchedule
        var encapsulated: Data
        
        init<PublicKey: HPKEDiffieHellmanPublicKey>(senderRoleWithCiphersuite ciphersuite: Ciphersuite, mode: Mode, psk: SymmetricKey?, pskID: Data?, pkR: PublicKey, info: Data) throws {
            let pkRKEM = try HPKE.DHKEM.PublicKey(pkR, kem: ciphersuite.kem)
            
            let encapsulationResult = try pkRKEM.encapsulate()
            encapsulated = encapsulationResult.encapsulated
            self.keySchedule = try KeySchedule(mode: mode,
                                               sharedSecret: encapsulationResult.sharedSecret, info: info, psk: psk, pskID: pskID, ciphersuite: ciphersuite)
        }
        
        init<SK: HPKEDiffieHellmanPrivateKey>(senderRoleWithCiphersuite ciphersuite: Ciphersuite, mode: Mode, psk: SymmetricKey?, pskID: Data?, pkR: SK.PublicKey, info: Data, skS: SK) throws {

            let skSKEM = try HPKE.DHKEM.PrivateKey(skS, kem: ciphersuite.kem)
            let pkRKEM = try HPKE.DHKEM.PublicKey(pkR, kem: ciphersuite.kem)
            
            let encapsulationResult = try skSKEM.authenticateAndEncapsulateTo(pkRKEM)
            
            encapsulated = encapsulationResult.encapsulated
            self.keySchedule = try KeySchedule(mode: mode, sharedSecret: encapsulationResult.sharedSecret, info: info, psk: psk, pskID: pskID, ciphersuite: ciphersuite)
        }
        
        init<PrivateKey: HPKEDiffieHellmanPrivateKey>(recipientRoleWithCiphersuite ciphersuite: Ciphersuite, mode: Mode, enc: Data, psk: SymmetricKey?, pskID: Data?, skR: PrivateKey, info: Data, pkS: PrivateKey.PublicKey?) throws {
            let skRKEM = try HPKE.DHKEM.PrivateKey(skR, kem: ciphersuite.kem)
            
            let sharedSecret: SymmetricKey
            if let pkS = pkS {
                sharedSecret = try skRKEM.decapsulate(enc, authenticating: pkS)
            } else {
                sharedSecret = try skRKEM.decapsulate(enc)
            }
            
            self.encapsulated = enc
            self.keySchedule = try KeySchedule(mode: mode, sharedSecret: sharedSecret, info: info, psk: psk, pskID: pskID, ciphersuite: ciphersuite)
        }
        
    }
}

#endif // Linux or !SwiftPM
