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

#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
fileprivate typealias BackingPublicKey = SecurityRSAPublicKey
fileprivate typealias BackingPrivateKey = SecurityRSAPrivateKey
#else
fileprivate typealias BackingPublicKey = BoringSSLRSAPublicKey
fileprivate typealias BackingPrivateKey = BoringSSLRSAPrivateKey
#endif

/// Types associated with the RSA algorithm
///
/// RSA is an asymmetric algorithm. In comparison to elliptic-curve equivalents, RSA requires relatively larger
/// key sizes to achieve equivalent security guarantees. These keys are inefficient to transmit and are often slow to
/// compute with, meaning that RSA-based cryptosystems perform poorly in comparison to elliptic-curve based systems.
/// Additionally, several common operating modes of RSA are insecure and unsafe to use.
///
/// When rolling out new cryptosystems, users should avoid RSA and use ECDSA or edDSA instead. RSA
/// support is provided for interoperability with legacy systems.
#if swift(>=5.8)
@_documentation(visibility: public)
public enum _RSA { }
#else
public enum _RSA { }
#endif

extension _RSA {
    public enum Signing { }
    public enum Encryption { }
}

extension _RSA.Signing {
    public struct PublicKey: Sendable {
        private var backing: BackingPublicKey

        /// Construct an RSA public key from a PEM representation.
        ///
        /// This constructor supports key sizes of 2048 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init(pemRepresentation: String) throws {
            self.backing = try BackingPublicKey(pemRepresentation: pemRepresentation)

            guard self.keySizeInBits >= 2048 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }
        
        /// Construct an RSA public key from a PEM representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        /// - Warning: Key sizes less than 2048 are not recommended and should only be used for compatibility reasons.
        public init(unsafePEMRepresentation pemRepresentation: String) throws {
            self.backing = try BackingPublicKey(pemRepresentation: pemRepresentation)
            
            guard self.keySizeInBits >= 1024 else {
                throw CryptoKitError.incorrectParameterSize
            }

        }

        /// Construct an RSA public key from a DER representation.
        ///
        /// This constructor supports key sizes of 2048 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
            self.backing = try BackingPublicKey(derRepresentation: derRepresentation)

            guard self.keySizeInBits >= 2048 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }
        
        /// Construct an RSA public key from a DER representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        /// - Warning: Key sizes less than 2048 are not recommended and should only be used for compatibility reasons.
        public init<Bytes: DataProtocol>(unsafeDERRepresentation derRepresentation: Bytes) throws {
            self.backing = try BackingPublicKey(derRepresentation: derRepresentation)

            guard self.keySizeInBits >= 1024 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }

        public var pkcs1DERRepresentation: Data {
            self.backing.pkcs1DERRepresentation
        }

        public var pkcs1PEMRepresentation: String {
            self.backing.pkcs1PEMRepresentation
        }

        public var derRepresentation: Data {
            self.backing.derRepresentation
        }

        public var pemRepresentation: String {
            self.backing.pemRepresentation
        }

        public var keySizeInBits: Int {
            self.backing.keySizeInBits
        }

        fileprivate init(_ backing: BackingPublicKey) {
            self.backing = backing
        }
    }
}

extension _RSA.Signing {
    public struct PrivateKey: Sendable {
        private var backing: BackingPrivateKey

        /// Construct an RSA private key from a PEM representation.
        ///
        /// This constructor supports key sizes of 2048 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init(pemRepresentation: String) throws {
            self.backing = try BackingPrivateKey(pemRepresentation: pemRepresentation)

            guard self.keySizeInBits >= 2048 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }
        
        /// Construct an RSA public key from a PEM representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        /// - Warning: Key sizes less than 2048 are not recommended and should only be used for compatibility reasons.
        public init(unsafePEMRepresentation pemRepresentation: String) throws {
            self.backing = try BackingPrivateKey(pemRepresentation: pemRepresentation)
            
            guard self.keySizeInBits >= 1024 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }

        /// Construct an RSA private key from a DER representation.
        ///
        /// This constructor supports key sizes of 2048 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
            self.backing = try BackingPrivateKey(derRepresentation: derRepresentation)

            guard self.keySizeInBits >= 2048 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }
        
        /// Construct an RSA public key from a DER representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        /// - Warning: Key sizes less than 2048 are not recommended and should only be used for compatibility reasons.
        public init<Bytes: DataProtocol>(unsafeDERRepresentation derRepresentation: Bytes) throws {
            self.backing = try BackingPrivateKey(derRepresentation: derRepresentation)

            guard self.keySizeInBits >= 1024 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }

        /// Randomly generate a new RSA private key of a given size.
        ///
        /// This constructor will refuse to generate keys smaller than 2048 bits. Callers that want to enforce minimum
        /// key size requirements should validate `keySize` before use.
        public init(keySize: _RSA.Signing.KeySize) throws {
            guard keySize.bitCount >= 2048 else {
                throw CryptoKitError.incorrectParameterSize
            }
            self.backing = try BackingPrivateKey(keySize: keySize)
        }
        
        /// Randomly generate a new RSA private key of a given size.
        ///
        /// This constructor will refuse to generate keys smaller than 1024 bits. Callers that want to enforce minimum
        /// key size requirements should validate `unsafekeySize` before use.
        /// - Warning: Key sizes less than 2048 are not recommended and should only be used for compatibility reasons.
        public init(unsafeKeySize keySize: _RSA.Signing.KeySize) throws {
            guard keySize.bitCount >= 1024 else {
                throw CryptoKitError.incorrectParameterSize
            }
            self.backing = try BackingPrivateKey(keySize: keySize)
        }

        public var derRepresentation: Data {
            self.backing.derRepresentation
        }

        public var pemRepresentation: String {
            self.backing.pemRepresentation
        }

        public var pkcs8PEMRepresentation: String {
            self.backing.pkcs8PEMRepresentation
        }

        public var keySizeInBits: Int {
            self.backing.keySizeInBits
        }

        public var publicKey: _RSA.Signing.PublicKey {
            _RSA.Signing.PublicKey(self.backing.publicKey)
        }
    }
}

extension _RSA.Signing {
    public struct RSASignature: Sendable, ContiguousBytes {
        public var rawRepresentation: Data

        public init<D: DataProtocol>(rawRepresentation: D) {
            self.rawRepresentation = Data(rawRepresentation)
        }
        
        internal init(signatureBytes: [UInt8]) {
            self.rawRepresentation = Data(signatureBytes)
        }

        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try self.rawRepresentation.withUnsafeBytes(body)
        }
    }
}

extension _RSA.Signing {
    public struct Padding: Sendable {
        internal enum Backing {
            case pkcs1v1_5
            case pss
            case pssZero // NOTE: this is internal-only, for RSABSSA.
        }

        internal var backing: Backing

        private init(_ backing: Backing) {
            self.backing = backing
        }

        /// PKCS#1 v1.5 padding as used in signing.
        ///
        /// As a note, PKCS#1 v1.5 padding is not known to be insecure in the signing operation at this time,
        /// merely in encryption. However, it's substantially less secure than PSS, and becoming comfortable with
        /// it in the signing context opens the door to the possibility of using it in the encryption context,
        /// where it is definitely known to be weak. So here we label it "insecure".
        public static let insecurePKCS1v1_5 = Self(.pkcs1v1_5)

        /// PSS padding using MGF1.
        ///
        /// MGF1 is parameterised with a hash function. The salt length will be the size of the digest from the given hash function.
        public static let PSS = Self(.pss)

        /// PSS padding using MGF1, with zero-length salt.
        ///
        /// MGF1 is parameterised with a hash function. The salt length is overriden to be zero.
        ///
        /// - NOTE: This is not API and is only accessible through the RSA Blind Signatures API.
        internal static let PSSZERO = Self(.pssZero)
    }
}

extension _RSA.Signing.PrivateKey {
    ///  Generates an RSA signature with the given key using the default padding.
    ///
    ///  The default padding is PSS using MGF1 with same hash function as produced the digest being
    ///  signed, and a salt that is as long as the digest. Note that this API will not select any
    ///  known-insecure digests.
    ///
    /// - Parameter digest: The digest to sign.
    /// - Returns: The RSA Signature.
    /// - Throws: If there is a failure producing the signature
    public func signature<D: Digest>(for digest: D) throws -> _RSA.Signing.RSASignature {
        return try self.signature(for: digest, padding: .PSS)
    }

    /// Generates an RSA signature with the given key using the default padding.
    ///
    /// SHA256 is used as the hash function. The default padding is PSS using MGF1 with SHA256
    /// and a 32-byte salt.
    ///
    /// - Parameter data: The data to sign.
    /// - Returns: The RSA Signature.
    /// - Throws: If there is a failure producing the signature.
    public func signature<D: DataProtocol>(for data: D) throws -> _RSA.Signing.RSASignature {
        return try self.signature(for: SHA256.hash(data: data), padding: .PSS)
    }

    /// Generates an RSA signature with the given key.
    ///
    /// - Parameter digest: The digest to sign.
    /// - Parameter padding: The padding to use.
    /// - Returns: The RSA Signature.
    /// - Throws: If there is a failure producing the signature
    public func signature<D: Digest>(for digest: D, padding: _RSA.Signing.Padding) throws -> _RSA.Signing.RSASignature {
        return try self.backing.signature(for: digest, padding: padding)
    }

    /// Generates an RSA signature with the given key.
    /// SHA256 is used as the hash function.
    ///
    /// - Parameter data: The data to sign.
    /// - Parameter padding: The padding to use.
    /// - Returns: The RSA Signature.
    /// - Throws: If there is a failure producing the signature.
    public func signature<D: DataProtocol>(for data: D, padding: _RSA.Signing.Padding) throws -> _RSA.Signing.RSASignature {
        return try self.signature(for: SHA256.hash(data: data), padding: padding)
    }
 }

extension _RSA.Signing.PublicKey {
    /// Verifies an RSA signature with the given padding over a given digest using the default padding.
    ///
    /// The default padding is PSS using MGF1 with same hash function as produced the digest being
    /// signed, and a salt that is as long as the digest. Note that this API will not select any
    /// known-insecure digests.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - digest: The digest that was signed.
    /// - Returns: True if the signature is valid, false otherwise.
    public func isValidSignature<D: Digest>(_ signature: _RSA.Signing.RSASignature, for digest: D) -> Bool {
        return self.isValidSignature(signature, for: digest, padding: .PSS)
    }

    /// Verifies an RSA signature with the given padding over a message with the default padding.
    ///
    /// SHA256 is used as the hash function. The default padding is PSS using MGF1 with SHA256
    /// and a 32-byte salt.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - data: The data that was signed.
    /// - Returns: True if the signature is valid, false otherwise.
    public func isValidSignature<D: DataProtocol>(_ signature: _RSA.Signing.RSASignature, for data: D) -> Bool {
        return self.isValidSignature(signature, for: SHA256.hash(data: data), padding: .PSS)
    }

    /// Verifies an RSA signature with the given padding over a given digest.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - digest: The digest that was signed.
    ///   - padding: The padding to use.
    /// - Returns: True if the signature is valid, false otherwise.
    public func isValidSignature<D: Digest>(_ signature: _RSA.Signing.RSASignature, for digest: D, padding: _RSA.Signing.Padding) -> Bool {
        return self.backing.isValidSignature(signature, for: digest, padding: padding)
    }

    /// Verifies an RSA signature with the given padding over a message.
    /// SHA256 is used as the hash function.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - data: The data that was signed.
    ///   - padding: The padding to use.
    /// - Returns: True if the signature is valid, false otherwise.
    public func isValidSignature<D: DataProtocol>(_ signature: _RSA.Signing.RSASignature, for data: D, padding: _RSA.Signing.Padding) -> Bool {
        return self.isValidSignature(signature, for: SHA256.hash(data: data), padding: padding)
    }
}

extension _RSA.Signing {
    public struct KeySize: Sendable {
        public let bitCount: Int

        /// RSA key size of 2048 bits
        public static let bits2048 = _RSA.Signing.KeySize(bitCount: 2048)

        /// RSA key size of 3072 bits
        public static let bits3072 = _RSA.Signing.KeySize(bitCount: 3072)

        /// RSA key size of 4096 bits
        public static let bits4096 = _RSA.Signing.KeySize(bitCount: 4096)

        /// RSA key size with a custom number of bits.
        ///
        /// Params:
        ///     - bitsCount: Positive integer that is a multiple of 8.
        public init(bitCount: Int) {
            precondition(bitCount % 8 == 0 && bitCount > 0)
            self.bitCount = bitCount
        }
    }
}

extension _RSA.Encryption {
    /// Identical to ``_RSA/Signing/PublicKey``.
    public struct PublicKey {
        private var backing: BackingPublicKey
        
        /// Construct an RSA public key from a PEM representation.
        ///
        /// This constructor supports key sizes of 2048 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init(pemRepresentation: String) throws {
            self.backing = try BackingPublicKey(pemRepresentation: pemRepresentation)
            guard self.keySizeInBits >= 2048, self.keySizeInBits % 8 == 0 else { throw CryptoKitError.incorrectParameterSize }
        }
        
        /// Construct an RSA public key from a PEM representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        /// - Warning: Key sizes less than 2048 are not recommended and should only be used for compatibility reasons.
        public init(unsafePEMRepresentation pemRepresentation: String) throws {
            self.backing = try BackingPublicKey(pemRepresentation: pemRepresentation)
            guard self.keySizeInBits >= 2048, self.keySizeInBits % 8 == 0 else { throw CryptoKitError.incorrectParameterSize }
        }

        /// Construct an RSA public key from a DER representation.
        ///
        /// This constructor supports key sizes of 2048 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
            self.backing = try BackingPublicKey(derRepresentation: derRepresentation)
            guard self.keySizeInBits >= 2048, self.keySizeInBits % 8 == 0 else { throw CryptoKitError.incorrectParameterSize }
        }
        
        /// Construct an RSA public key from a DER representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        /// - Warning: Key sizes less than 2048 are not recommended and should only be used for compatibility reasons.
        public init<Bytes: DataProtocol>(unsafeDERRepresentation derRepresentation: Bytes) throws {
            self.backing = try BackingPublicKey(derRepresentation: derRepresentation)
            guard self.keySizeInBits >= 1024, self.keySizeInBits % 8 == 0 else { throw CryptoKitError.incorrectParameterSize }
        }

        public var pkcs1DERRepresentation: Data { self.backing.pkcs1DERRepresentation }
        public var pkcs1PEMRepresentation: String { self.backing.pkcs1PEMRepresentation }
        public var derRepresentation: Data { self.backing.derRepresentation }
        public var pemRepresentation: String { self.backing.pemRepresentation }
        public var keySizeInBits: Int { self.backing.keySizeInBits }
        fileprivate init(_ backing: BackingPublicKey) { self.backing = backing }
    }
    
    /// Identical to ``_RSA/Signing/PrivateKey``.
    public struct PrivateKey {
        private var backing: BackingPrivateKey

        /// Construct an RSA private key from a PEM representation.
        ///
        /// This constructor supports key sizes of 2048 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init(pemRepresentation: String) throws {
            self.backing = try BackingPrivateKey(pemRepresentation: pemRepresentation)
            guard self.keySizeInBits >= 2048, self.keySizeInBits % 8 == 0 else { throw CryptoKitError.incorrectParameterSize }
        }
        
        /// Construct an RSA public key from a PEM representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        /// - Warning: Key sizes less than 2048 are not recommended and should only be used for compatibility reasons.
        public init(unsafePEMRepresentation pemRepresentation: String) throws {
            self.backing = try BackingPrivateKey(pemRepresentation: pemRepresentation)
            guard self.keySizeInBits >= 1024, self.keySizeInBits % 8 == 0 else { throw CryptoKitError.incorrectParameterSize }
        }

        /// Construct an RSA private key from a DER representation.
        ///
        /// This constructor supports key sizes of 2048 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        public init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
            self.backing = try BackingPrivateKey(derRepresentation: derRepresentation)
            guard self.keySizeInBits >= 2048, self.keySizeInBits % 8 == 0 else { throw CryptoKitError.incorrectParameterSize }
        }
        
        /// Construct an RSA public key from a DER representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        /// - Warning: Key sizes less than 2048 are not recommended and should only be used for compatibility reasons.
        public init<Bytes: DataProtocol>(unsafeDERRepresentation derRepresentation: Bytes) throws {
            self.backing = try BackingPrivateKey(derRepresentation: derRepresentation)
            guard self.keySizeInBits >= 1024, self.keySizeInBits % 8 == 0 else { throw CryptoKitError.incorrectParameterSize }
        }

        /// Randomly generate a new RSA private key of a given size.
        ///
        /// This constructor will refuse to generate keys smaller than 2048 bits. Callers that want to enforce minimum
        /// key size requirements should validate `keySize` before use.
        public init(keySize: _RSA.Signing.KeySize) throws {
            guard keySize.bitCount >= 2048 else { throw CryptoKitError.incorrectParameterSize }
            self.backing = try BackingPrivateKey(keySize: keySize)
        }
        
        /// Randomly generate a new RSA private key of a given size.
        ///
        /// This constructor will refuse to generate keys smaller than 1024 bits. Callers that want to enforce minimum
        /// key size requirements should validate `keySize` before use.
        /// - Warning: Key sizes less than 2048 are not recommended and should only be used for compatibility reasons.
        public init(unsafeKeySize keySize: _RSA.Signing.KeySize) throws {
            guard keySize.bitCount >= 1024 else { throw CryptoKitError.incorrectParameterSize }
            self.backing = try BackingPrivateKey(keySize: keySize)
        }
        
        public var derRepresentation: Data { self.backing.derRepresentation }
        public var pemRepresentation: String { self.backing.pemRepresentation }
        public var pkcs8PEMRepresentation: String { self.backing.pkcs8PEMRepresentation }
        public var keySizeInBits: Int { self.backing.keySizeInBits }
        public var publicKey: _RSA.Encryption.PublicKey { .init(self.backing.publicKey) }
    }
}

extension _RSA.Encryption {
    public struct Padding: Sendable {
        internal enum Backing {
            case pkcs1_oaep(Digest)
        }

        internal var backing: Backing

        private init(_ backing: Backing) {
            self.backing = backing
        }
        
        /// PKCS#1 OAEP padding
        ///
        /// As defined by [RFC 8017 § 7.1](https://datatracker.ietf.org/doc/html/rfc8017#section-7.1).
        public static let PKCS1_OAEP = Self(.pkcs1_oaep(.sha1))
        public static let PKCS1_OAEP_SHA256 = Self(.pkcs1_oaep(.sha256))
    }

    internal enum Digest {
        case sha1
        case sha256
    }
}

extension _RSA.Encryption.PrivateKey {
    /// Decrypt a message encrypted with this key's public key and using the specified padding mode.
    ///
    /// > Important: The size of the data to decrypt must be equal to the block size of the key (e.g.
    ///   `keySizeInBits / 8`). Attempting to decrypt data of the wrong size will fail.
    public func decrypt<D: DataProtocol>(_ data: D, padding: _RSA.Encryption.Padding) throws -> Data {
        return try self.backing.decrypt(data, padding: padding)
    }
}

extension _RSA.Encryption.PublicKey {
    /// Return the maximum amount of data in bytes this key can encrypt in a single operation when using
    /// the specified padding mode.
    ///
    /// ## Common values:
    ///
    /// Key size|Padding|Max length
    /// -|-|-
    /// 2048|PKCS-OAEP|214 bytes
    /// 3072|PKCS-OAEP|342 bytes
    /// 4096|PKCS-OAEP|470 bytes
    public func maximumEncryptSize(with padding: _RSA.Encryption.Padding) -> Int {
        switch padding.backing {
        case .pkcs1_oaep:
            return (self.keySizeInBits / 8) - 42
        }
    }
    
    /// Encrypt a message with this key, using the specified padding mode.
    ///
    /// > Important: The size of the data to encrypt _must_ not exceed the modulus of the key (e.g.
    ///   `keySizeInBits / 8`), minus any additional space required by the padding mode. Attempting to
    ///   encrypt data larger than this will fail. Use ``maximumEncryptSize(with:)`` to determine
    ///   exactly how many bytes can be encrypted by the key.
    public func encrypt<D: DataProtocol>(_ data: D, padding: _RSA.Encryption.Padding) throws -> Data {
        return try self.backing.encrypt(data, padding: padding)
    }
}

extension _RSA {
    static let PKCS1KeyType = "RSA PRIVATE KEY"

    static let PKCS8KeyType = "PRIVATE KEY"

    static let PKCS1PublicKeyType = "RSA PUBLIC KEY"

    static let SPKIPublicKeyType = "PUBLIC KEY"
}
