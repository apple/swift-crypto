//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import Foundation
import Crypto

#if canImport(Security)
@_implementationOnly import Security

internal struct SecurityRSAPublicKey {
    private var backing: SecKey

    init(pemRepresentation: String) throws {
        let document = try ASN1.PEMDocument(pemString: pemRepresentation)
        self = try .init(derRepresentation: document.derBytes)
    }

    init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
        let keyAttributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
        ]
        let data = Data(derRepresentation)
        var error: Unmanaged<CFError>? = nil
        let key = SecKeyCreateWithData(data as CFData, keyAttributes as CFDictionary, &error)

        guard let unwrappedKey = key else {
            // If this returns nil, error must be set.
            throw error!.takeRetainedValue() as Error
        }

        self.backing = unwrappedKey
    }

    var pkcs1DERRepresentation: Data {
        var error: Unmanaged<CFError>? = nil
        let representation = SecKeyCopyExternalRepresentation(self.backing, &error)
        return representation! as Data
    }

    var pkcs1PEMRepresentation: String {
        return ASN1.PEMDocument(type: _RSA.PKCS1PublicKeyType, derBytes: self.pkcs1DERRepresentation).pemString
    }

    var derRepresentation: Data {
        return Data(spkiBytesForPKCS1Bytes: self.pkcs1DERRepresentation)
    }

    var pemRepresentation: String {
        return ASN1.PEMDocument(type: _RSA.SPKIPublicKeyType, derBytes: self.derRepresentation).pemString
    }

    var keySizeInBits: Int {
        let attributes = SecKeyCopyAttributes(self.backing)! as NSDictionary
        return (attributes[kSecAttrKeySizeInBits]! as! NSNumber).intValue
    }

    fileprivate init(_ backing: SecKey) {
        self.backing = backing
    }
}


internal struct SecurityRSAPrivateKey {
    private var backing: SecKey

    init(pemRepresentation: String) throws {
        let document = try ASN1.PEMDocument(pemString: pemRepresentation)

        switch document.type {
        case _RSA.PKCS1KeyType:
            // This is what is expected by Security.framework
            self = try .init(derRepresentation: document.derBytes)
        case _RSA.PKCS8KeyType:
            guard let pkcs8Bytes = document.derBytes.pkcs8RSAKeyBytes else {
                throw _CryptoRSAError.invalidPEMDocument
            }
            self = try .init(derRepresentation: pkcs8Bytes)
        default:
            throw _CryptoRSAError.invalidPEMDocument
        }

    }

    init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
        let keyAttributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        ]
        let data = Data(derRepresentation)
        var error: Unmanaged<CFError>? = nil

        // We can't know in DER if this is PKCS8 or PKCS1 without just trying to decode it.
        let keyData: Data
        if let pkcs8Data = data.pkcs8RSAKeyBytes {
            keyData = pkcs8Data
        } else {
            keyData = data
        }

        let key = SecKeyCreateWithData(keyData as CFData, keyAttributes as CFDictionary, &error)

        guard let unwrappedKey = key else {
            // If this returns nil, error must be set.
            throw error!.takeRetainedValue() as Error
        }

        self.backing = unwrappedKey
    }

    init(keySize: _RSA.Signing.KeySize) throws {
        let keyAttributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits: keySize.bitCount
        ]
        var error: Unmanaged<CFError>? = nil
        let key = SecKeyCreateRandomKey(keyAttributes as CFDictionary, &error)

        guard let unwrappedKey = key else {
            // If this returns nil, error must be set.
            throw error!.takeRetainedValue() as Error
        }

        self.backing = unwrappedKey
    }

    var derRepresentation: Data {
        var error: Unmanaged<CFError>? = nil
        let representation = SecKeyCopyExternalRepresentation(self.backing, &error)
        return representation! as Data
    }

    var pemRepresentation: String {
        return ASN1.PEMDocument(type: _RSA.PKCS1KeyType, derBytes: self.derRepresentation).pemString
    }

    var keySizeInBits: Int {
        let attributes = SecKeyCopyAttributes(self.backing)! as NSDictionary
        return (attributes[kSecAttrKeySizeInBits]! as! NSNumber).intValue
    }

    var publicKey: SecurityRSAPublicKey {
        SecurityRSAPublicKey(SecKeyCopyPublicKey(self.backing)!)
    }
}

extension SecurityRSAPrivateKey {
    internal func signature<D: Digest>(for digest: D, padding: _RSA.Signing.Padding) throws -> _RSA.Signing.RSASignature {
        let algorithm = try SecKeyAlgorithm(digestType: D.self, padding: padding)
        let digestToSign = Data(digest)
        var error: Unmanaged<CFError>? = nil
        let sig = SecKeyCreateSignature(self.backing, algorithm, digestToSign as CFData, &error)

        guard let signature = sig else {
            // If this returns nil, error must be set.
            throw error!.takeRetainedValue() as Error
        }

        return _RSA.Signing.RSASignature(rawRepresentation: signature as Data)
    }
 }

extension SecurityRSAPublicKey {
    func isValidSignature<D: Digest>(_ signature: _RSA.Signing.RSASignature, for digest: D, padding: _RSA.Signing.Padding) -> Bool {
        do {
            let algorithm = try SecKeyAlgorithm(digestType: D.self, padding: padding)
            let digestToValidate = Data(digest)
            var error: Unmanaged<CFError>? = nil
            let result = SecKeyVerifySignature(self.backing,
                                               algorithm,
                                               digestToValidate as CFData,
                                               signature.rawRepresentation as CFData,
                                               &error)

            return result
        } catch {
            return false
        }
    }
}

extension SecKeyAlgorithm {
    fileprivate init<D: Digest>(digestType: D.Type = D.self, padding: _RSA.Signing.Padding) throws {
        switch digestType {
        case is Insecure.SHA1.Digest.Type:
            switch padding.backing {
            case .pss:
                self = .rsaSignatureDigestPSSSHA1
            case .pkcs1v1_5:
                self = .rsaSignatureDigestPKCS1v15SHA1
            }
        case is SHA256.Digest.Type:
            switch padding.backing {
            case .pss:
                self = .rsaSignatureDigestPSSSHA256
            case .pkcs1v1_5:
                self = .rsaSignatureDigestPKCS1v15SHA256
            }
        case is SHA384.Digest.Type:
            switch padding.backing {
            case .pss:
                self = .rsaSignatureDigestPSSSHA384
            case .pkcs1v1_5:
                self = .rsaSignatureDigestPKCS1v15SHA384
            }
        case is SHA512.Digest.Type:
            switch padding.backing {
            case .pss:
                self = .rsaSignatureDigestPSSSHA512
            case .pkcs1v1_5:
                self = .rsaSignatureDigestPKCS1v15SHA512
            }
        default:
            throw CryptoKitError.incorrectParameterSize
        }
    }
}

extension Data {
    init<D: Digest>(_ digest: D) {
        self = digest.withUnsafeBytes { Data($0) }
    }

    /// A partial PKCS8 DER prefix. This specifically is the version and private key algorithm identifier.
    private static let partialPKCS8Prefix = Data(
        [
            0x02, 0x01, 0x00,  // Version, INTEGER 0
            0x30, 0x0d,        // SEQUENCE, length 13
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,  // rsaEncryption OID
            0x05, 0x00         // NULL
        ]
    )

    var pkcs8RSAKeyBytes: Data? {
        // This is PKCS8. A bit awkward now. Rather than bring over the fully-fledged ASN.1 code from
        // the main module and all its dependencies, we have a little hand-rolled verifier. To be a proper
        // PKCS8 key, this should match:
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
        // We know the version and algorithm identifier, so we can just strip the bytes we'd expect to see here. We do validate
        // them though.
        precondition(self.startIndex == 0)

        guard self.count >= 4 + Data.partialPKCS8Prefix.count + 4 else {
            return nil
        }

        // First byte will be the tag for sequence, 0x30.
        guard self[0] == 0x30 else {
            return nil
        }

        // The next few bytes will be a length. We'll expect it to be 3 bytes long, with the first byte telling us
        // that it's 3 bytes long.
        let lengthLength = Int(self[1])
        guard lengthLength == 0x82 else {
            return nil
        }

        let length = Int(self[2]) << 8 | Int(self[3])
        guard length == self.count - 4 else {
            return nil
        }

        // Now we can check the version through the algorithm identifier against the hardcoded values.
        guard self.dropFirst(4).prefix(Data.partialPKCS8Prefix.count) == Data.partialPKCS8Prefix else {
            return nil
        }

        // Ok, the last check are the next 4 bytes, which should now be the tag for OCTET STRING followed by another length.
        guard self[4 + Data.partialPKCS8Prefix.count] == 0x04,
        self[4 + Data.partialPKCS8Prefix.count + 1] == 0x82 else {
            return nil
        }

        let octetStringLength = Int(self[4 + Data.partialPKCS8Prefix.count + 2]) << 8 |
                                Int(self[4 + Data.partialPKCS8Prefix.count + 3])
        guard octetStringLength == self.count - 4 - Data.partialPKCS8Prefix.count - 4 else {
            return nil
        }

        return self.dropFirst(4 + Data.partialPKCS8Prefix.count + 4)
    }

    // Corresponds to the ASN.1 encoding of the RSA AlgorithmIdentifier:
    //
    // SEQUENCE of OID (:rsaEncryption) and NULL.
    static let rsaAlgorithmIdentifierBytes = Data([
        0x30, 0x0D,                                             // SEQUENCE, Length 13
        0x06, 0x09,                                             // OID, length 9
        0x2A, 0x86 , 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,  // 1.2.840.113549.1.1.1 :rsaEncryption
        0x05, 0x00,                                             // NULL, length 0

    ])

    fileprivate init(spkiBytesForPKCS1Bytes pkcs1Bytes: Data) {
        // This does an ad-hoc SPKI encode. Ideally we'd bring over the entire ASN.1 stack, but it's not worth doing
        // for just this one use-case.
        let keyLength = (pkcs1Bytes.count + 1)
        let bitStringOverhead = 1 + keyLength._bytesNeededToEncodeASN1Length  // 1 byte for tag.
        let totalLengthOfSequencePayload = Self.rsaAlgorithmIdentifierBytes.count + bitStringOverhead + keyLength

        var bytes = Data()
        bytes.reserveCapacity(1 + totalLengthOfSequencePayload._bytesNeededToEncodeASN1Length + totalLengthOfSequencePayload)

        bytes.append(0x30)  // SEQUENCE marker.
        bytes.appendAsASN1NodeLength(totalLengthOfSequencePayload)
        bytes.append(Self.rsaAlgorithmIdentifierBytes)

        bytes.append(0x03)  // BITSTRING marker
        bytes.appendAsASN1NodeLength(keyLength)
        bytes.append(UInt8(0))  // No padding bits
        bytes.append(contentsOf: pkcs1Bytes)

        self = bytes
    }

    fileprivate mutating func appendAsASN1NodeLength(_ length: Int) {
        let bytesNeeded = length._bytesNeededToEncodeASN1Length

        if bytesNeeded == 1 {
            self.append(UInt8(length))
        } else {
            // We first write the number of length bytes
            // we need, setting the high bit. Then we write the bytes of the length.
            self.append(0x80 | UInt8(bytesNeeded - 1))

            for shift in (0..<(bytesNeeded - 1)).reversed() {
                // Shift and mask the integer.
                self.append(UInt8(truncatingIfNeeded: (length >> (shift * 8))))
            }
        }
    }
}

extension Int {
    fileprivate var _bytesNeededToEncodeASN1Length: Int {
        // ASN.1 lengths are in two forms. If we can store the length in 7 bits, we should:
        // that requires only one byte. Otherwise, we need multiple bytes: work out how many,
        // plus one for the length of the length bytes.
        if self <= 0x7F {
            return 1
        } else {
            // We need to work out how many bytes we need. There are many fancy bit-twiddling
            // ways of doing this, but honestly we don't do this enough to need them, so we'll
            // do it the easy way. This math is done on UInt because it makes the shift semantics clean.
            // We save a branch here because we can never overflow this addition.
            return UInt(self).neededBytes &+ 1
        }
    }
}

extension UInt {
    // Bytes needed to store a given integer in 7 bit bytes.
    fileprivate var neededBytes: Int {
        let neededBits = self.bitWidth - self.leadingZeroBitCount
        return (neededBits + 7) / 8
    }
}

#endif
