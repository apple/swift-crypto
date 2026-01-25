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
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Crypto
import CryptoBoringWrapper
import SwiftASN1

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
fileprivate typealias BackingPublicKey = BoringSSLRSAPublicKey
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
fileprivate typealias BackingPrivateKey = BoringSSLRSAPrivateKey

/// Types associated with the RSA algorithm
///
/// RSA is an asymmetric algorithm. In comparison to elliptic-curve equivalents, RSA requires relatively larger
/// key sizes to achieve equivalent security guarantees. These keys are inefficient to transmit and are often slow to
/// compute with, meaning that RSA-based cryptosystems perform poorly in comparison to elliptic-curve based systems.
/// Additionally, several common operating modes of RSA are insecure and unsafe to use.
///
/// When rolling out new cryptosystems, users should avoid RSA and use ECDSA or edDSA instead. RSA
/// support is provided for interoperability with legacy systems.
@_documentation(visibility: public)
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public enum _RSA { }

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension _RSA {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum Signing { }
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum Encryption { }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension _RSA.Signing {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public struct PublicKey: Sendable {
        public struct Primitives: Sendable, Hashable {
            public var modulus: Data
            public var publicExponent: Data

            public init(modulus: Data, publicExponent: Data) {
                self.modulus = modulus
                self.publicExponent = publicExponent
            }
        }

        private var backing: BackingPublicKey

        /// Construct an RSA public key from a PEM representation.
        ///
        /// This constructor supports key sizes of 2048 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        /// Parameters from RSA PSS keys will be stripped.
        public init(pemRepresentation: String) throws {
            let derBytes = try PEMDocument(pemString: pemRepresentation).derBytes

            try self.init(derRepresentation: derBytes)
        }
        
        /// Construct an RSA public key from a PEM representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        /// Parameters from RSA PSS keys will be stripped.
        /// - Warning: Key sizes less than 2048 are not recommended and should only be used for compatibility reasons.
        public init(unsafePEMRepresentation pemRepresentation: String) throws {
            let derBytes = try PEMDocument(pemString: pemRepresentation).derBytes

            try self.init(unsafeDERRepresentation: derBytes)
        }

        /// Construct an RSA public key from a DER representation.
        ///
        /// This constructor supports key sizes of 2048 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        /// Parameters from RSA PSS keys will be stripped.
        public init<Bytes: DataProtocol>(derRepresentation: Bytes) throws {
            let sanitizedDer = try SubjectPublicKeyInfo.stripRsaPssParameters(derEncoded: [UInt8](derRepresentation))

            self.backing = try BackingPublicKey(derRepresentation: sanitizedDer)

            guard self.keySizeInBits >= 2048 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }
        
        /// Construct an RSA public key from a DER representation.
        ///
        /// This constructor supports key sizes of 1024 bits or more. Users should validate that key sizes are appropriate
        /// for their use-case.
        /// Parameters from RSA PSS keys will be stripped.
        /// - Warning: Key sizes less than 2048 are not recommended and should only be used for compatibility reasons.
        public init<Bytes: DataProtocol>(unsafeDERRepresentation derRepresentation: Bytes) throws {
            let sanitizedDer = try SubjectPublicKeyInfo.stripRsaPssParameters(derEncoded: [UInt8](derRepresentation))

            self.backing = try BackingPublicKey(derRepresentation: sanitizedDer)

            guard self.keySizeInBits >= 1024 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }

        /// Construct an RSA public key with the specified parameters.
        public init(n: some ContiguousBytes, e: some ContiguousBytes) throws {
            self.backing = try BackingPublicKey(n: n, e: e)
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

        public func getKeyPrimitives() throws -> Primitives {
            let (n, e) = self.backing.getKeyPrimitives()
            return Primitives(modulus: n, publicExponent: e)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension _RSA.Signing {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
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
        
        /// Construct an RSA private key from a PEM representation.
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
        
        /// Construct an RSA private key from a DER representation.
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

        /// Construct an RSA private key with the specified parameters.
        public init(n: some ContiguousBytes, e: some ContiguousBytes, d: some ContiguousBytes, p: some ContiguousBytes, q: some ContiguousBytes) throws {
            self.backing = try BackingPrivateKey(n: n, e: e, d: d, p: p, q: q)
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

        /// A Distinguished Encoding Rules (DER) encoded representation of the private key in PKCS#8 format.
        public var pkcs8DERRepresentation: Data {
            self.backing.pkcs8DERRepresentation
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

        /// Construct a private key with the specified parameters.
        ///
        /// The use of this API is strongly discouraged for performance reasons,
        /// as it requires the factorization of the modulus, which is resource-intensive.
        /// It is recommended to use the other initializers to construct a private key,
        /// unless you have only the modulus, public exponent, and private exponent 
        /// to construct the key.
        ///
        /// - Parameters:
        ///   - n: modulus of the key
        ///   - e: public exponent of the key
        ///   - d: private exponent of the key
        public static func _createFromNumbers(n: some ContiguousBytes, e: some ContiguousBytes, d: some ContiguousBytes) throws -> Self {
            let (p, q) = try _RSA.extractPrimeFactors(
                n: try ArbitraryPrecisionInteger(bytes: n), 
                e: try ArbitraryPrecisionInteger(bytes: e), 
                d: try ArbitraryPrecisionInteger(bytes: d)
            )

            return try Self.init(
                n: n, e: e, d: d, 
                p: try Data(bytesOf: p, paddedToSize: p.byteCount), 
                q: try Data(bytesOf: q, paddedToSize: q.byteCount)
            )
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension _RSA.Signing {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension _RSA.Signing {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension _RSA.Signing {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension _RSA.Encryption {
    /// Identical to ``_RSA/Signing/PublicKey``.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public struct PublicKey {
        public struct Primitives: Sendable, Hashable {
            public var modulus: Data
            public var publicExponent: Data

            public init(modulus: Data, publicExponent: Data) {
                self.modulus = modulus
                self.publicExponent = publicExponent
            }
        }

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
            guard self.keySizeInBits >= 1024, self.keySizeInBits % 8 == 0 else { throw CryptoKitError.incorrectParameterSize }
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

        /// Construct an RSA public key with the specified parameters.
        public init(n: some ContiguousBytes, e: some ContiguousBytes) throws {
            self.backing = try BackingPublicKey(n: n, e: e)
        }

        public var pkcs1DERRepresentation: Data { self.backing.pkcs1DERRepresentation }
        public var pkcs1PEMRepresentation: String { self.backing.pkcs1PEMRepresentation }
        public var derRepresentation: Data { self.backing.derRepresentation }
        public var pemRepresentation: String { self.backing.pemRepresentation }
        public var keySizeInBits: Int { self.backing.keySizeInBits }
        fileprivate init(_ backing: BackingPublicKey) { self.backing = backing }

        public func getKeyPrimitives() throws -> Primitives {
            let (n, e) = self.backing.getKeyPrimitives()
            return Primitives(modulus: n, publicExponent: e)
        }
    }
    
    /// Identical to ``_RSA/Signing/PrivateKey``.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
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


        /// Construct an RSA private key with the specified parameters.
        public init(n: some ContiguousBytes, e: some ContiguousBytes, d: some ContiguousBytes, p: some ContiguousBytes, q: some ContiguousBytes) throws {
            self.backing = try BackingPrivateKey(n: n, e: e, d: d, p: p, q: q)
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

        /// Construct a private key with the specified parameters.
        ///
        /// The use of this API is strongly discouraged for performance reasons,
        /// as it requires the factorization of the modulus, which is resource-intensive.
        /// It is recommended to use the other initializers to construct a private key,
        /// unless you have only the modulus, public exponent, and private exponent 
        /// to construct the key.
        ///
        /// - Parameters:
        ///   - n: modulus of the key
        ///   - e: public exponent of the key
        ///   - d: private exponent of the key
        public static func _createFromNumbers(n: some ContiguousBytes, e: some ContiguousBytes, d: some ContiguousBytes) throws -> Self {
            let (p, q) = try _RSA.extractPrimeFactors(
                n: try ArbitraryPrecisionInteger(bytes: n), 
                e: try ArbitraryPrecisionInteger(bytes: e), 
                d: try ArbitraryPrecisionInteger(bytes: d)
            )

            return try Self.init(
                n: n, e: e, d: d, 
                p: try Data(bytesOf: p, paddedToSize: p.byteCount), 
                q: try Data(bytesOf: q, paddedToSize: q.byteCount)
            )
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension _RSA.Encryption {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public struct Padding: Sendable {
        internal enum Backing {
            case _weakAndInsecure_pkcs1v1_5
            case pkcs1_oaep(Digest)
        }

        internal var backing: Backing

        private init(_ backing: Backing) {
            self.backing = backing
        }

        /// PKCS#1 v1.5 padding
        ///
        /// As defined by [RFC 8017 § 7.2](https://datatracker.ietf.org/doc/html/rfc8017#section-7.2).
        ///
        /// This padding exists only for legacy compatibility and is known to be
        /// weak and insecure. This algorithm is vulnerable to chosen-ciphertext
        /// attacks outlined in http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf.
        ///
        /// When you have a choice, you should always favor OAEP over this.
        public static let _WEAK_AND_INSECURE_PKCS_V1_5 = Self(._weakAndInsecure_pkcs1v1_5)

        /// PKCS#1 OAEP padding
        ///
        /// As defined by [RFC 8017 § 7.1](https://datatracker.ietf.org/doc/html/rfc8017#section-7.1).
        public static let PKCS1_OAEP = Self(.pkcs1_oaep(.sha1))
        public static let PKCS1_OAEP_SHA256 = Self(.pkcs1_oaep(.sha256))
    }

    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    internal enum Digest {
        case sha1
        case sha256

        /// Returns the number of bits in the resulting hash
        var hashBitLength: Int {
            switch self {
            case .sha1: return 160
            case .sha256: return 256
            }
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension _RSA.Encryption.PrivateKey {
    /// Decrypt a message encrypted with this key's public key and using the specified padding mode.
    ///
    /// > Important: The size of the data to decrypt must be equal to the block size of the key (e.g.
    ///   `keySizeInBits / 8`). Attempting to decrypt data of the wrong size will fail.
    public func decrypt<D: DataProtocol>(_ data: D, padding: _RSA.Encryption.Padding) throws -> Data {
        return try self.backing.decrypt(data, padding: padding)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension _RSA.Encryption.PublicKey {
    /// Return the maximum amount of data in bytes this key can encrypt in a single operation when using
    /// the specified padding mode.
    ///
    /// ## Common values (for PKCS1 OAEP SHA1):
    ///
    /// Key size|Padding|Max length
    /// -|-|-
    /// 2048|PKCS-OAEP|214 bytes
    /// 3072|PKCS-OAEP|342 bytes
    /// 4096|PKCS-OAEP|470 bytes
    public func maximumEncryptSize(with padding: _RSA.Encryption.Padding) -> Int {
        switch padding.backing {
        case ._weakAndInsecure_pkcs1v1_5:
            // https://www.rfc-editor.org/rfc/rfc8017#section-7.2
            return (self.keySizeInBits / 8) - 11
        case let .pkcs1_oaep(Digest):
            // https://datatracker.ietf.org/doc/html/rfc8017#section-7.1.1
            return (self.keySizeInBits / 8) - (2 * Digest.hashBitLength / 8) - 2
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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension _RSA {
    static let PKCS1KeyType = "RSA PRIVATE KEY"

    static let PKCS8KeyType = "PRIVATE KEY"

    static let PKCS1PublicKeyType = "RSA PUBLIC KEY"

    static let SPKIPublicKeyType = "PUBLIC KEY"
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension _RSA {
    static func extractPrimeFactors(
        n: ArbitraryPrecisionInteger, 
        e: ArbitraryPrecisionInteger, 
        d: ArbitraryPrecisionInteger
    ) throws -> (p: ArbitraryPrecisionInteger, q: ArbitraryPrecisionInteger) {
        // This is based on the proof of fact 1 in https://www.ams.org/notices/199902/boneh.pdf
        let k = (d * e) - 1
        let t = k.trailingZeroBitCount
        let r = k >> t

        guard k.isEven else {
            throw CryptoKitError.incorrectParameterSize
        }

        var y: ArbitraryPrecisionInteger = 0
        var i = 1

        let context = try FiniteFieldArithmeticContext(fieldSize: n)

        while i <= 100 {
            let g = try ArbitraryPrecisionInteger.random(inclusiveMin: 2, exclusiveMax: n)
            y = try context.pow(g, r)

            guard y != 1, y != n - 1 else {
                continue
            }

            var j = 1
            var x: ArbitraryPrecisionInteger

            while j <= t &- 1 {
                x = try context.pow(y, 2)

                guard x != 1, x != n - 1 else {
                    break
                }

                y = x
                j &+= 1
            }

            x = try context.pow(y, 2)
            if x == 1 {
                let p = try ArbitraryPrecisionInteger.gcd(y - 1, n)
                let q = n / p

                return (p, q)
            }

            i &+= 1
        }

        throw CryptoKitError.incorrectParameterSize
    }
}
