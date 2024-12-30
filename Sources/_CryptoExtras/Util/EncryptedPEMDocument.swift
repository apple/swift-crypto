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
struct EncryptedPEMDocument: PEMRepresentable {
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
    
    func serialize(into coder: inout SwiftASN1.DER.Serializer) throws {
        try coder.appendConstructedNode(identifier: .sequence) { coder in
            try self.algorithmIdentifier.serialize(into: &coder)
            try self.encryptedData.serialize(into: &coder)
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
            let pbkdf2Params = try PBKDF2Parameters(asn1Any: pbes2Params.keyDerivationFunction.parameters)
            
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
                try encryptedData.bytes.withUnsafeBufferPointer { encryptedPtr in
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
                    
                    var output = [UInt8](repeating: 0, count: encryptedData.bytes.count)
                    
                    var ks1 = DES_key_schedule(), ks2 = DES_key_schedule(), ks3 = DES_key_schedule()
                    try derivedKey.withUnsafeBytes { keyPtr in
                        guard keyPtr.count >= 24 else { throw _CryptoRSAError.invalidPEMDocument }
                        
                        let keyBytes = keyPtr.bindMemory(to: UInt8.self)
                        
                        var key1 = try toDESBlock(keyBytes)
                        var key2 = try toDESBlock(keyBytes, paddedBy: 8)
                        var key3 = try toDESBlock(keyBytes, paddedBy: 16)
                        
                        CCryptoBoringSSL_DES_set_key_unchecked(&key1, &ks1)
                        CCryptoBoringSSL_DES_set_key_unchecked(&key2, &ks2)
                        CCryptoBoringSSL_DES_set_key_unchecked(&key3, &ks3)
                    }
                    
                    var iv = try pbes2Params.encryptionScheme.encryptionAlgorithmParameters.bytes.withUnsafeBytes { ivPtr -> DES_cblock in
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

extension KDF.Insecure.PBKDF2.HashFunction {
    static func from(objectIdentifier: ASN1ObjectIdentifier) -> Self? {
        switch objectIdentifier.oidComponents {
        case [2, 16, 840, 1, 101, 3, 4, 2, 1],
            [1, 2, 840, 113549, 2, 9]: // hmacWithSHA256
            .sha256
        case [2, 16, 840, 1, 101, 3, 4, 2, 2]:
            .sha384
        case [2, 16, 840, 1, 101, 3, 4, 2, 3]:
            .sha512
        default: nil
        }
    }
}

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

struct KeyDerivationFunction: DERImplicitlyTaggable {
    static var defaultIdentifier: ASN1Identifier { .sequence }
    
    let algorithm: ASN1ObjectIdentifier
    let parameters: ASN1Any
    
    init(algorithm: ASN1ObjectIdentifier, parameters: ASN1Any) {
        self.algorithm = algorithm
        self.parameters = parameters
    }
    
    init(derEncoded: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(derEncoded, identifier: identifier) { nodes in
            let algorithm = try ASN1ObjectIdentifier(derEncoded: &nodes)
            let parameters = try ASN1Any(derEncoded: &nodes)
            
            return .init(algorithm: algorithm, parameters: parameters)
        }
    }
    
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try self.algorithm.serialize(into: &coder)
            try self.parameters.serialize(into: &coder)
        }
    }
}

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

//  PBKDF2-params ::= SEQUENCE {
//    salt CHOICE {
//      specified       OCTET STRING,
//      otherSource     AlgorithmIdentifier {{PBKDF2-SaltSources}}
//    },
//    iterationCount    INTEGER (1..MAX),
//    keyLength         INTEGER (1..MAX) OPTIONAL,
//    prf               AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1
//  }
struct PBKDF2Parameters: DERImplicitlyTaggable {
    struct HashFunction: DERImplicitlyTaggable {
        static var defaultIdentifier: ASN1Identifier { .sequence }
        
        let objectIdentifer: ASN1ObjectIdentifier
        let null: ASN1Null
        
        init(objectIdentifer: ASN1ObjectIdentifier, null: ASN1Null) {
            self.objectIdentifer = objectIdentifer
            self.null = null
        }
        
        init(derEncoded: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
            self = try DER.sequence(derEncoded, identifier: identifier) { nodes in
                let objectIdentifer = try ASN1ObjectIdentifier(derEncoded: &nodes)
                let null = try ASN1Null(derEncoded: &nodes)
                
                return .init(objectIdentifer: objectIdentifer, null: null)
            }
        }
        
        func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
            try coder.appendConstructedNode(identifier: identifier) { coder in
                try self.objectIdentifer.serialize(into: &coder)
                try self.null.serialize(into: &coder)
            }
        }
    }
        
    static var defaultIdentifier: ASN1Identifier { .sequence }
    
    let salt: ASN1OctetString
    let iterationCount: any ASN1IntegerRepresentable
    let hashFunction: HashFunction
    
    init(salt: ASN1OctetString, iterationCount: any ASN1IntegerRepresentable, hashFunction: HashFunction) {
        self.salt = salt
        self.iterationCount = iterationCount
        self.hashFunction = hashFunction
    }
    
    init(derEncoded: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(derEncoded, identifier: identifier) { nodes in
            let salt = try ASN1OctetString(derEncoded: &nodes)
            let iterationCount = try Int(derEncoded: &nodes)
            let hashFunction = try HashFunction(derEncoded: &nodes)
            
            return .init(salt: salt, iterationCount: iterationCount, hashFunction: hashFunction)
        }
    }
    
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try self.salt.serialize(into: &coder)
            try self.iterationCount.serialize(into: &coder)
            try self.hashFunction.serialize(into: &coder)
        }
    }
}
