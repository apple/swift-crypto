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

import Crypto
import SwiftASN1
import Foundation
@_implementationOnly import CCryptoBoringSSL

// EncryptedPrivateKeyInfo ::= SEQUENCE {
//   encryptionAlgorithm  EncryptionAlgorithmIdentifier,
//   encryptedData    EncryptedData
// }
//
// EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
//
// EncryptedData ::= OCTET STRING
struct EncryptedPEMDocument: PEMParseable {
    let algorithmIdentifier: RFC5480AlgorithmIdentifier
    let encryptedData: ASN1OctetString
    
    init(algorithmIdentifier: RFC5480AlgorithmIdentifier, encryptedData: ASN1OctetString) {
        self.algorithmIdentifier = algorithmIdentifier
        self.encryptedData = encryptedData
    }
    
    static var defaultPEMDiscriminator: String {
        "ENCRYPTED PRIVATE KEY"
    }
    
    init(derEncoded node: ASN1Node) throws {
        self = try DER.sequence(node, identifier: .sequence) { nodes in
            let algorithmIdentifier = try RFC5480AlgorithmIdentifier(derEncoded: &nodes)
            let encryptedData = try ASN1OctetString(derEncoded: &nodes)
            
            return .init(algorithmIdentifier: algorithmIdentifier, encryptedData: encryptedData)
        }
    }
    
    func decrypt(withPassword password: String) throws -> PEMDocument {
        let algorithm = self.algorithmIdentifier.algorithm
        
        guard let parameters = self.algorithmIdentifier.parameters else {
            throw _CryptoRSAError.invalidPEMDocument
        }
        
        switch algorithm {
        case .pkcs5PBES2:
            let pbes2Params = try PBES2Parameters(asn1Any: parameters)
            let pbkdf2Params = try KeyDerivationFunction.PBKDF2Parameters(asn1Any: pbes2Params.keyDerivationFunction.parameters)
            
            let hashFunction = pbkdf2Params.hashFunction
            
            let derivedKey = try KDF.Insecure.PBKDF2.deriveKey(
                from: [UInt8](password.utf8),
                salt: pbkdf2Params.salt.bytes,
                using: .from(objectIdentifier: hashFunction.objectIdentifer)!,
                outputByteCount: pbes2Params.encryptionScheme.encryptionAlgorithm.encryptionAlgorithmKeyLength,
                unsafeUncheckedRounds: pbkdf2Params.iterationCount as! Int
            )
            
            let decryption: Data? = switch pbes2Params.encryptionScheme.encryptionAlgorithm {
            case .aes128_CBC, .aes192_CBC, .aes256_CBC:
                try AES._CBC.decrypt(
                    encryptedData.bytes,
                    using: derivedKey,
                    iv: .init(ivBytes: pbes2Params.encryptionScheme.encryptionAlgorithmParameters.bytes)
                )
            case .des_EDE3_CBC:
                try TripleDES.CBC.decrypt(
                    encryptedData.bytes,
                    using: derivedKey,
                    iv: pbes2Params.encryptionScheme.encryptionAlgorithmParameters.bytes
                )
            default: nil
            }
            
            return PEMDocument(type: "PRIVATE KEY", derBytes: [UInt8](decryption!))
        default:
            break
        }
        
        return try PEMDocument(pemString: "")
    }
}

extension ASN1ObjectIdentifier {
    static let pkcs5PBES2 = ASN1ObjectIdentifier("1.2.840.113549.1.5.13")
    static let pkcs5PBKDF2 = ASN1ObjectIdentifier("1.2.840.113549.1.5.12")
    static let pkcs5PBE_MD5_DES_CBC = ASN1ObjectIdentifier("1.2.840.113549.1.5.3")
    static let pkcs5PBE_MD5_RC2_CBC = ASN1ObjectIdentifier("1.2.840.113549.1.5.6")
    static let pkcs5PBE_SHA1_DES_CBC = ASN1ObjectIdentifier("1.2.840.113549.1.5.10")
    static let pkcs5PBE_SHA1_RC2_CBC = ASN1ObjectIdentifier("1.2.840.113549.1.5.11")
    
    static let pkcs5Scrypt = ASN1ObjectIdentifier("1.3.6.1.4.1.11591.4.11")
}

// Encryption schemes
extension ASN1ObjectIdentifier {
    static let aes128_CBC = ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.2")
    static let aes192_CBC = ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.22")
    static let aes256_CBC = ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.42")
    static let des_EDE3_CBC = ASN1ObjectIdentifier("1.2.840.113549.3.7")
}

extension ASN1ObjectIdentifier {
    var encryptionAlgorithmKeyLength: Int {
        switch self {
        case .aes128_CBC: 16
        case .aes192_CBC: 24
        case .aes256_CBC: 32
        case .des_EDE3_CBC: 24
        default: fatalError("Not an encryption algorithm")
        }
    }
}

fileprivate enum TripleDES {
    fileprivate enum CBC {
        static func decrypt(_ encryptedData: ArraySlice<UInt8>, using key: SymmetricKey, iv: ArraySlice<UInt8>) throws -> Data {
            try encryptedData.withUnsafeBytes { encryptedPtr in
                func toDESBlock(_ bytes: UnsafeBufferPointer<UInt8>, paddedBy padding: Int = 0) throws -> DES_cblock {
                    guard let baseAddress = bytes.baseAddress else {
                        throw _CryptoRSAError.invalidPEMDocument
                    }
                    
                    let bytes = baseAddress.advanced(by: padding)
                    return DES_cblock(bytes: (
                        bytes[0], bytes[1], bytes[2], bytes[3],
                        bytes[4], bytes[5], bytes[6], bytes[7]
                    ))
                }
                
                var output = [UInt8](repeating: 0, count: encryptedData.count)
                
                var ks1 = DES_key_schedule(), ks2 = DES_key_schedule(), ks3 = DES_key_schedule()
                try key.withUnsafeBytes { keyPtr in
                    guard keyPtr.count >= 24 else { throw _CryptoRSAError.invalidPEMDocument }
                    
                    let keyBytes = keyPtr.bindMemory(to: UInt8.self)
                    
                    var key1 = try toDESBlock(keyBytes)
                    var key2 = try toDESBlock(keyBytes, paddedBy: 8)
                    var key3 = try toDESBlock(keyBytes, paddedBy: 16)
                    
                    CCryptoBoringSSL_DES_set_key_unchecked(&key1, &ks1)
                    CCryptoBoringSSL_DES_set_key_unchecked(&key2, &ks2)
                    CCryptoBoringSSL_DES_set_key_unchecked(&key3, &ks3)
                }
                
                var iv = try iv.withUnsafeBytes { ivPtr -> DES_cblock in
                    let ivBytes = ivPtr.bindMemory(to: UInt8.self)
                    return try toDESBlock(ivBytes)
                }
                
                CCryptoBoringSSL_DES_ede3_cbc_encrypt(
                    encryptedPtr.baseAddress!,
                    &output,
                    encryptedPtr.count,
                    &ks1,
                    &ks2,
                    &ks3,
                    &iv,
                    0
                )
                
                var result = Data(output)
                try result.trimCBCPadding()
                return result
            }
        }
    }
}
