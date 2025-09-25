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
#if (!CRYPTO_IN_SWIFTPM_FORCE_BUILD_API) || CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias NISTCurvePublicKeyImpl = CoreCryptoNISTCurvePublicKeyImpl
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias NISTCurvePrivateKeyImpl = CoreCryptoNISTCurvePrivateKeyImpl
#else
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias NISTCurvePublicKeyImpl = OpenSSLNISTCurvePublicKeyImpl
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias NISTCurvePrivateKeyImpl = OpenSSLNISTCurvePrivateKeyImpl
#endif

#if CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
public import SwiftSystem
#else
#if canImport(FoundationEssentials)
public import FoundationEssentials
#else
public import Foundation
#endif
#endif

// MARK: - Generated file, do NOT edit
// any edits of this file WILL be overwritten and thus discarded
// see section `gyb` in `README` for details.

// MARK: - P256 + Signing
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P256 {
    
    /// A mechanism used to create or verify a cryptographic signature using
    /// the NIST P-256 elliptic curve digital signature algorithm (ECDSA).
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum Signing: Sendable {

        /// A P-256 public key used to verify cryptographic signatures.
        @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
        public struct PublicKey: NISTECPublicKey, Sendable {
            var impl: NISTCurvePublicKeyImpl<P256>

            /// Creates a P-256 public key for signing from a collection of bytes.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A raw representation of the key as a collection of
            /// contiguous bytes.
            public init<D: ContiguousBytes>(rawRepresentation: D) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(rawRepresentation: rawRepresentation)
            }

            /// Creates a P-256 public key for signing from a compact
            /// representation of the key.
            ///
            /// - Parameters:
            ///   - compactRepresentation: A compact representation of the key
            /// as a collection of contiguous bytes.
            public init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(compactRepresentation: compactRepresentation)
            }

            /// Creates a P-256 public key for signing from an ANSI x9.63
            /// representation.
            ///
            /// - Parameters:
            ///   - x963Representation: An ANSI x9.63 representation of the key.
            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(x963Representation: x963Representation)
            }
            
            /// Creates a P-256 public key for signing from a compressed representation of
            /// the key.
            ///
            /// - Parameters:
            ///   - compressedRepresentation: A compressed representation of the key as a collection
            /// of contiguous bytes.
            public init<Bytes: ContiguousBytes>(compressedRepresentation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(compressedRepresentation: compressedRepresentation)
            }

#if !hasFeature(Embedded)
            /// Creates a P-256 public key for signing from a Privacy-Enhanced Mail
            /// (PEM) representation.
            ///
            /// - Parameters:
            ///   - pemRepresentation: A PEM representation of the key.
            public init(pemRepresentation: String) throws(CryptoKitMetaError) {
                let pem = try ASN1.PEMDocument(pemString: pemRepresentation)
                guard pem.type == "PUBLIC KEY" else {
                    throw CryptoKitASN1Error.invalidPEMDocument
                }
                self = try .init(derRepresentation: pem.derBytes)
            }
#endif

            /// Creates a P-256 public key for signing from a Distinguished Encoding
            /// Rules (DER) encoded representation.
            ///
            /// - Parameters:
            ///   - derRepresentation: A DER-encoded representation of the key.
            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws(CryptoKitMetaError) where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)
                let parsed = try ASN1.SubjectPublicKeyInfo(asn1Encoded: bytes)
                self = try .init(x963Representation: parsed.key)
            }

            init(impl: NISTCurvePublicKeyImpl<P256>) {
                self.impl = impl
            }

            /// A compact representation of the public key.
            public var compactRepresentation: Data? { impl.compactRepresentation }
            
            /// A full representation of the public key.
            public var rawRepresentation: Data { impl.rawRepresentation }
            
            /// An ANSI x9.63 representation of the public key.
            public var x963Representation: Data { impl.x963Representation }

            /// A compressed representation of the public key.
            public var compressedRepresentation: Data { impl.compressedRepresentation }
            
            /// A Distinguished Encoding Rules (DER) encoded representation of the public key.
            public var derRepresentation: Data {
                let spki = ASN1.SubjectPublicKeyInfo(algorithmIdentifier: .ecdsaP256, key: Array(self.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(spki)
                return Data(serializer.serializedBytes)
            }

#if !hasFeature(Embedded)
            /// A Privacy-Enhanced Mail (PEM) representation of the public key.
            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PUBLIC KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
#endif
        }

        /// A P-256 private key used to create cryptographic signatures.
        @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
        public struct PrivateKey: NISTECPrivateKey, Sendable {
            let impl: NISTCurvePrivateKeyImpl<P256>

            /// Creates a random P-256 private key for signing.
            ///
            /// Keys that use a compact point encoding enable shorter public keys, but aren’t
            /// compliant with FIPS certification. If your app requires FIPS certification,
            /// create a key with ``init(rawRepresentation:)``.
            ///
            /// - Parameters:
            ///   - compactRepresentable: A Boolean value that indicates whether CryptoKit
            /// creates the key with the structure to enable compact point encoding.
            public init(compactRepresentable: Bool = true) {
                impl = NISTCurvePrivateKeyImpl(compactRepresentable: compactRepresentable)
            }

            /// Creates a P-256 private key for signing from an ANSI x9.63
            /// representation.
            ///
            /// - Parameters:
            ///   - x963Representation: An ANSI x9.63 representation of the key.
            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePrivateKeyImpl(x963: x963Representation)
            }

            /// Creates a P-256 private key for signing from a collection of bytes.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A raw representation of the key as a collection of
            /// contiguous bytes.
            public init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePrivateKeyImpl(data: rawRepresentation)
            }

#if !hasFeature(Embedded)
            /// Creates a P-256 private key for signing from a Privacy-Enhanced Mail
            /// PEM) representation.
            ///
            /// - Parameters:
            ///   - pemRepresentation: A PEM representation of the key.
            public init(pemRepresentation: String) throws(CryptoKitMetaError) {
                let pem = try ASN1.PEMDocument(pemString: pemRepresentation)

                switch pem.type {
                case "EC PRIVATE KEY":
                    let parsed = try ASN1.SEC1PrivateKey(asn1Encoded: Array(pem.derBytes))
                    self = try .init(rawRepresentation: parsed.privateKey)
                case "PRIVATE KEY":
                    let parsed = try ASN1.PKCS8PrivateKey(asn1Encoded: Array(pem.derBytes))
                    self = try .init(rawRepresentation: parsed.privateKey.privateKey)
                default:
                    throw CryptoKitASN1Error.invalidPEMDocument
                }
            }
#endif

            /// Creates a P-256 private key for signing from a Distinguished Encoding
            /// Rules (DER) encoded representation.
            ///
            /// - Parameters:
            ///   - derRepresentation: A DER-encoded representation of the key.
            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws(CryptoKitMetaError) where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)

                // We have to try to parse this twice because we have no information about what kind of key this is.
                // We try with PKCS#8 first, and then fall back to SEC.1.

                do {
                    let key = try ASN1.PKCS8PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey.privateKey)
                } catch {
                    let key = try ASN1.SEC1PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey)
                }
            }

            init(impl: NISTCurvePrivateKeyImpl<P256>) {
                self.impl = impl
            }

            /// The corresponding public key.
            public var publicKey: P256.Signing.PublicKey {
                return PublicKey(impl: impl.publicKey())
            }

            /// A data representation of the private key.
            public var rawRepresentation: Data { impl.rawRepresentation }
            
            /// An ANSI x9.63 representation of the private key.
            public var x963Representation: Data { impl.x963Representation }

            /// A Distinguished Encoding Rules (DER) encoded representation of the private key.
            public var derRepresentation: Data {
                let pkey = ASN1.PKCS8PrivateKey(algorithm: .ecdsaP256, privateKey: Array(self.rawRepresentation), publicKey: Array(self.publicKey.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(pkey)
                return Data(serializer.serializedBytes)
            }

#if !hasFeature(Embedded)
            /// A Privacy-Enhanced Mail (PEM) representation of the private key.
            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PRIVATE KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
#endif
        }
    }
}
// MARK: - P256 + KeyAgreement
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P256 {
    
    /// A mechanism used to create a shared secret between two users by
    /// performing NIST P-256 elliptic curve Diffie Hellman (ECDH) key
    /// exchange.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum KeyAgreement: Sendable {

        /// A P-256 public key used for key agreement.
        @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
        public struct PublicKey: NISTECPublicKey, Sendable {
            var impl: NISTCurvePublicKeyImpl<P256>

            /// Creates a P-256 public key for key agreement from a collection of bytes.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A raw representation of the key as a collection of
            /// contiguous bytes.
            public init<D: ContiguousBytes>(rawRepresentation: D) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(rawRepresentation: rawRepresentation)
            }

            /// Creates a P-256 public key for key agreement from a compact
            /// representation of the key.
            ///
            /// - Parameters:
            ///   - compactRepresentation: A compact representation of the key
            /// as a collection of contiguous bytes.
            public init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(compactRepresentation: compactRepresentation)
            }

            /// Creates a P-256 public key for key agreement from an ANSI x9.63
            /// representation.
            ///
            /// - Parameters:
            ///   - x963Representation: An ANSI x9.63 representation of the key.
            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(x963Representation: x963Representation)
            }
            
            /// Creates a P-256 public key for key agreement from a compressed representation of
            /// the key.
            ///
            /// - Parameters:
            ///   - compressedRepresentation: A compressed representation of the key as a collection
            /// of contiguous bytes.
            public init<Bytes: ContiguousBytes>(compressedRepresentation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(compressedRepresentation: compressedRepresentation)
            }

#if !hasFeature(Embedded)
            /// Creates a P-256 public key for key agreement from a Privacy-Enhanced Mail
            /// (PEM) representation.
            ///
            /// - Parameters:
            ///   - pemRepresentation: A PEM representation of the key.
            public init(pemRepresentation: String) throws(CryptoKitMetaError) {
                let pem = try ASN1.PEMDocument(pemString: pemRepresentation)
                guard pem.type == "PUBLIC KEY" else {
                    throw CryptoKitASN1Error.invalidPEMDocument
                }
                self = try .init(derRepresentation: pem.derBytes)
            }
#endif

            /// Creates a P-256 public key for key agreement from a Distinguished Encoding
            /// Rules (DER) encoded representation.
            ///
            /// - Parameters:
            ///   - derRepresentation: A DER-encoded representation of the key.
            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws(CryptoKitMetaError) where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)
                let parsed = try ASN1.SubjectPublicKeyInfo(asn1Encoded: bytes)
                self = try .init(x963Representation: parsed.key)
            }

            init(impl: NISTCurvePublicKeyImpl<P256>) {
                self.impl = impl
            }

            /// A compact representation of the public key.
            public var compactRepresentation: Data? { impl.compactRepresentation }
            
            /// A full representation of the public key.
            public var rawRepresentation: Data { impl.rawRepresentation }
            
            /// An ANSI x9.63 representation of the public key.
            public var x963Representation: Data { impl.x963Representation }

            /// A compressed representation of the public key.
            public var compressedRepresentation: Data { impl.compressedRepresentation }
            
            /// A Distinguished Encoding Rules (DER) encoded representation of the public key.
            public var derRepresentation: Data {
                let spki = ASN1.SubjectPublicKeyInfo(algorithmIdentifier: .ecdsaP256, key: Array(self.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(spki)
                return Data(serializer.serializedBytes)
            }

#if !hasFeature(Embedded)
            /// A Privacy-Enhanced Mail (PEM) representation of the public key.
            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PUBLIC KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
#endif
        }

        /// A P-256 private key used for key agreement.
        @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
        public struct PrivateKey: NISTECPrivateKey, Sendable {
            let impl: NISTCurvePrivateKeyImpl<P256>

            /// Creates a random P-256 private key for key agreement.
            ///
            /// Keys that use a compact point encoding enable shorter public keys, but aren’t
            /// compliant with FIPS certification. If your app requires FIPS certification,
            /// create a key with ``init(rawRepresentation:)``.
            ///
            /// - Parameters:
            ///   - compactRepresentable: A Boolean value that indicates whether CryptoKit
            /// creates the key with the structure to enable compact point encoding.
            public init(compactRepresentable: Bool = true) {
                impl = NISTCurvePrivateKeyImpl(compactRepresentable: compactRepresentable)
            }

            /// Creates a P-256 private key for key agreement from an ANSI x9.63
            /// representation.
            ///
            /// - Parameters:
            ///   - x963Representation: An ANSI x9.63 representation of the key.
            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePrivateKeyImpl(x963: x963Representation)
            }

            /// Creates a P-256 private key for key agreement from a collection of bytes.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A raw representation of the key as a collection of
            /// contiguous bytes.
            public init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePrivateKeyImpl(data: rawRepresentation)
            }

#if !hasFeature(Embedded)
            /// Creates a P-256 private key for key agreement from a Privacy-Enhanced Mail
            /// PEM) representation.
            ///
            /// - Parameters:
            ///   - pemRepresentation: A PEM representation of the key.
            public init(pemRepresentation: String) throws(CryptoKitMetaError) {
                let pem = try ASN1.PEMDocument(pemString: pemRepresentation)

                switch pem.type {
                case "EC PRIVATE KEY":
                    let parsed = try ASN1.SEC1PrivateKey(asn1Encoded: Array(pem.derBytes))
                    self = try .init(rawRepresentation: parsed.privateKey)
                case "PRIVATE KEY":
                    let parsed = try ASN1.PKCS8PrivateKey(asn1Encoded: Array(pem.derBytes))
                    self = try .init(rawRepresentation: parsed.privateKey.privateKey)
                default:
                    throw CryptoKitASN1Error.invalidPEMDocument
                }
            }
#endif

            /// Creates a P-256 private key for key agreement from a Distinguished Encoding
            /// Rules (DER) encoded representation.
            ///
            /// - Parameters:
            ///   - derRepresentation: A DER-encoded representation of the key.
            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws(CryptoKitMetaError) where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)

                // We have to try to parse this twice because we have no information about what kind of key this is.
                // We try with PKCS#8 first, and then fall back to SEC.1.

                do {
                    let key = try ASN1.PKCS8PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey.privateKey)
                } catch {
                    let key = try ASN1.SEC1PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey)
                }
            }

            init(impl: NISTCurvePrivateKeyImpl<P256>) {
                self.impl = impl
            }

            /// The corresponding public key.
            public var publicKey: P256.KeyAgreement.PublicKey {
                return PublicKey(impl: impl.publicKey())
            }

            /// A data representation of the private key.
            public var rawRepresentation: Data { impl.rawRepresentation }
            
            /// An ANSI x9.63 representation of the private key.
            public var x963Representation: Data { impl.x963Representation }

            /// A Distinguished Encoding Rules (DER) encoded representation of the private key.
            public var derRepresentation: Data {
                let pkey = ASN1.PKCS8PrivateKey(algorithm: .ecdsaP256, privateKey: Array(self.rawRepresentation), publicKey: Array(self.publicKey.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(pkey)
                return Data(serializer.serializedBytes)
            }

#if !hasFeature(Embedded)
            /// A Privacy-Enhanced Mail (PEM) representation of the private key.
            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PRIVATE KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
#endif
        }
    }
}
// MARK: - P384 + Signing
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P384 {
    
    /// A mechanism used to create or verify a cryptographic signature using
    /// the NIST P-384 elliptic curve digital signature algorithm (ECDSA).
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum Signing: Sendable {

        /// A P-384 public key used to verify cryptographic signatures.
        @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
        public struct PublicKey: NISTECPublicKey, Sendable {
            var impl: NISTCurvePublicKeyImpl<P384>

            /// Creates a P-384 public key for signing from a collection of bytes.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A raw representation of the key as a collection of
            /// contiguous bytes.
            public init<D: ContiguousBytes>(rawRepresentation: D) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(rawRepresentation: rawRepresentation)
            }

            /// Creates a P-384 public key for signing from a compact
            /// representation of the key.
            ///
            /// - Parameters:
            ///   - compactRepresentation: A compact representation of the key
            /// as a collection of contiguous bytes.
            public init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(compactRepresentation: compactRepresentation)
            }

            /// Creates a P-384 public key for signing from an ANSI x9.63
            /// representation.
            ///
            /// - Parameters:
            ///   - x963Representation: An ANSI x9.63 representation of the key.
            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(x963Representation: x963Representation)
            }
            
            /// Creates a P-384 public key for signing from a compressed representation of
            /// the key.
            ///
            /// - Parameters:
            ///   - compressedRepresentation: A compressed representation of the key as a collection
            /// of contiguous bytes.
            public init<Bytes: ContiguousBytes>(compressedRepresentation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(compressedRepresentation: compressedRepresentation)
            }

#if !hasFeature(Embedded)
            /// Creates a P-384 public key for signing from a Privacy-Enhanced Mail
            /// (PEM) representation.
            ///
            /// - Parameters:
            ///   - pemRepresentation: A PEM representation of the key.
            public init(pemRepresentation: String) throws(CryptoKitMetaError) {
                let pem = try ASN1.PEMDocument(pemString: pemRepresentation)
                guard pem.type == "PUBLIC KEY" else {
                    throw CryptoKitASN1Error.invalidPEMDocument
                }
                self = try .init(derRepresentation: pem.derBytes)
            }
#endif

            /// Creates a P-384 public key for signing from a Distinguished Encoding
            /// Rules (DER) encoded representation.
            ///
            /// - Parameters:
            ///   - derRepresentation: A DER-encoded representation of the key.
            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws(CryptoKitMetaError) where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)
                let parsed = try ASN1.SubjectPublicKeyInfo(asn1Encoded: bytes)
                self = try .init(x963Representation: parsed.key)
            }

            init(impl: NISTCurvePublicKeyImpl<P384>) {
                self.impl = impl
            }

            /// A compact representation of the public key.
            public var compactRepresentation: Data? { impl.compactRepresentation }
            
            /// A full representation of the public key.
            public var rawRepresentation: Data { impl.rawRepresentation }
            
            /// An ANSI x9.63 representation of the public key.
            public var x963Representation: Data { impl.x963Representation }

            /// A compressed representation of the public key.
            public var compressedRepresentation: Data { impl.compressedRepresentation }
            
            /// A Distinguished Encoding Rules (DER) encoded representation of the public key.
            public var derRepresentation: Data {
                let spki = ASN1.SubjectPublicKeyInfo(algorithmIdentifier: .ecdsaP384, key: Array(self.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(spki)
                return Data(serializer.serializedBytes)
            }

#if !hasFeature(Embedded)
            /// A Privacy-Enhanced Mail (PEM) representation of the public key.
            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PUBLIC KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
#endif
        }

        /// A P-384 private key used to create cryptographic signatures.
        @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
        public struct PrivateKey: NISTECPrivateKey, Sendable {
            let impl: NISTCurvePrivateKeyImpl<P384>

            /// Creates a random P-384 private key for signing.
            ///
            /// Keys that use a compact point encoding enable shorter public keys, but aren’t
            /// compliant with FIPS certification. If your app requires FIPS certification,
            /// create a key with ``init(rawRepresentation:)``.
            ///
            /// - Parameters:
            ///   - compactRepresentable: A Boolean value that indicates whether CryptoKit
            /// creates the key with the structure to enable compact point encoding.
            public init(compactRepresentable: Bool = true) {
                impl = NISTCurvePrivateKeyImpl(compactRepresentable: compactRepresentable)
            }

            /// Creates a P-384 private key for signing from an ANSI x9.63
            /// representation.
            ///
            /// - Parameters:
            ///   - x963Representation: An ANSI x9.63 representation of the key.
            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePrivateKeyImpl(x963: x963Representation)
            }

            /// Creates a P-384 private key for signing from a collection of bytes.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A raw representation of the key as a collection of
            /// contiguous bytes.
            public init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePrivateKeyImpl(data: rawRepresentation)
            }

#if !hasFeature(Embedded)
            /// Creates a P-384 private key for signing from a Privacy-Enhanced Mail
            /// PEM) representation.
            ///
            /// - Parameters:
            ///   - pemRepresentation: A PEM representation of the key.
            public init(pemRepresentation: String) throws(CryptoKitMetaError) {
                let pem = try ASN1.PEMDocument(pemString: pemRepresentation)

                switch pem.type {
                case "EC PRIVATE KEY":
                    let parsed = try ASN1.SEC1PrivateKey(asn1Encoded: Array(pem.derBytes))
                    self = try .init(rawRepresentation: parsed.privateKey)
                case "PRIVATE KEY":
                    let parsed = try ASN1.PKCS8PrivateKey(asn1Encoded: Array(pem.derBytes))
                    self = try .init(rawRepresentation: parsed.privateKey.privateKey)
                default:
                    throw CryptoKitASN1Error.invalidPEMDocument
                }
            }
#endif

            /// Creates a P-384 private key for signing from a Distinguished Encoding
            /// Rules (DER) encoded representation.
            ///
            /// - Parameters:
            ///   - derRepresentation: A DER-encoded representation of the key.
            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws(CryptoKitMetaError) where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)

                // We have to try to parse this twice because we have no information about what kind of key this is.
                // We try with PKCS#8 first, and then fall back to SEC.1.

                do {
                    let key = try ASN1.PKCS8PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey.privateKey)
                } catch {
                    let key = try ASN1.SEC1PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey)
                }
            }

            init(impl: NISTCurvePrivateKeyImpl<P384>) {
                self.impl = impl
            }

            /// The corresponding public key.
            public var publicKey: P384.Signing.PublicKey {
                return PublicKey(impl: impl.publicKey())
            }

            /// A data representation of the private key.
            public var rawRepresentation: Data { impl.rawRepresentation }
            
            /// An ANSI x9.63 representation of the private key.
            public var x963Representation: Data { impl.x963Representation }

            /// A Distinguished Encoding Rules (DER) encoded representation of the private key.
            public var derRepresentation: Data {
                let pkey = ASN1.PKCS8PrivateKey(algorithm: .ecdsaP384, privateKey: Array(self.rawRepresentation), publicKey: Array(self.publicKey.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(pkey)
                return Data(serializer.serializedBytes)
            }

#if !hasFeature(Embedded)
            /// A Privacy-Enhanced Mail (PEM) representation of the private key.
            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PRIVATE KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
#endif
        }
    }
}
// MARK: - P384 + KeyAgreement
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P384 {
    
    /// A mechanism used to create a shared secret between two users by
    /// performing NIST P-384 elliptic curve Diffie Hellman (ECDH) key
    /// exchange.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum KeyAgreement: Sendable {

        /// A P-384 public key used for key agreement.
        @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
        public struct PublicKey: NISTECPublicKey, Sendable {
            var impl: NISTCurvePublicKeyImpl<P384>

            /// Creates a P-384 public key for key agreement from a collection of bytes.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A raw representation of the key as a collection of
            /// contiguous bytes.
            public init<D: ContiguousBytes>(rawRepresentation: D) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(rawRepresentation: rawRepresentation)
            }

            /// Creates a P-384 public key for key agreement from a compact
            /// representation of the key.
            ///
            /// - Parameters:
            ///   - compactRepresentation: A compact representation of the key
            /// as a collection of contiguous bytes.
            public init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(compactRepresentation: compactRepresentation)
            }

            /// Creates a P-384 public key for key agreement from an ANSI x9.63
            /// representation.
            ///
            /// - Parameters:
            ///   - x963Representation: An ANSI x9.63 representation of the key.
            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(x963Representation: x963Representation)
            }
            
            /// Creates a P-384 public key for key agreement from a compressed representation of
            /// the key.
            ///
            /// - Parameters:
            ///   - compressedRepresentation: A compressed representation of the key as a collection
            /// of contiguous bytes.
            public init<Bytes: ContiguousBytes>(compressedRepresentation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(compressedRepresentation: compressedRepresentation)
            }

#if !hasFeature(Embedded)
            /// Creates a P-384 public key for key agreement from a Privacy-Enhanced Mail
            /// (PEM) representation.
            ///
            /// - Parameters:
            ///   - pemRepresentation: A PEM representation of the key.
            public init(pemRepresentation: String) throws(CryptoKitMetaError) {
                let pem = try ASN1.PEMDocument(pemString: pemRepresentation)
                guard pem.type == "PUBLIC KEY" else {
                    throw CryptoKitASN1Error.invalidPEMDocument
                }
                self = try .init(derRepresentation: pem.derBytes)
            }
#endif

            /// Creates a P-384 public key for key agreement from a Distinguished Encoding
            /// Rules (DER) encoded representation.
            ///
            /// - Parameters:
            ///   - derRepresentation: A DER-encoded representation of the key.
            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws(CryptoKitMetaError) where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)
                let parsed = try ASN1.SubjectPublicKeyInfo(asn1Encoded: bytes)
                self = try .init(x963Representation: parsed.key)
            }

            init(impl: NISTCurvePublicKeyImpl<P384>) {
                self.impl = impl
            }

            /// A compact representation of the public key.
            public var compactRepresentation: Data? { impl.compactRepresentation }
            
            /// A full representation of the public key.
            public var rawRepresentation: Data { impl.rawRepresentation }
            
            /// An ANSI x9.63 representation of the public key.
            public var x963Representation: Data { impl.x963Representation }

            /// A compressed representation of the public key.
            public var compressedRepresentation: Data { impl.compressedRepresentation }
            
            /// A Distinguished Encoding Rules (DER) encoded representation of the public key.
            public var derRepresentation: Data {
                let spki = ASN1.SubjectPublicKeyInfo(algorithmIdentifier: .ecdsaP384, key: Array(self.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(spki)
                return Data(serializer.serializedBytes)
            }

#if !hasFeature(Embedded)
            /// A Privacy-Enhanced Mail (PEM) representation of the public key.
            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PUBLIC KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
#endif
        }

        /// A P-384 private key used for key agreement.
        @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
        public struct PrivateKey: NISTECPrivateKey, Sendable {
            let impl: NISTCurvePrivateKeyImpl<P384>

            /// Creates a random P-384 private key for key agreement.
            ///
            /// Keys that use a compact point encoding enable shorter public keys, but aren’t
            /// compliant with FIPS certification. If your app requires FIPS certification,
            /// create a key with ``init(rawRepresentation:)``.
            ///
            /// - Parameters:
            ///   - compactRepresentable: A Boolean value that indicates whether CryptoKit
            /// creates the key with the structure to enable compact point encoding.
            public init(compactRepresentable: Bool = true) {
                impl = NISTCurvePrivateKeyImpl(compactRepresentable: compactRepresentable)
            }

            /// Creates a P-384 private key for key agreement from an ANSI x9.63
            /// representation.
            ///
            /// - Parameters:
            ///   - x963Representation: An ANSI x9.63 representation of the key.
            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePrivateKeyImpl(x963: x963Representation)
            }

            /// Creates a P-384 private key for key agreement from a collection of bytes.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A raw representation of the key as a collection of
            /// contiguous bytes.
            public init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePrivateKeyImpl(data: rawRepresentation)
            }

#if !hasFeature(Embedded)
            /// Creates a P-384 private key for key agreement from a Privacy-Enhanced Mail
            /// PEM) representation.
            ///
            /// - Parameters:
            ///   - pemRepresentation: A PEM representation of the key.
            public init(pemRepresentation: String) throws(CryptoKitMetaError) {
                let pem = try ASN1.PEMDocument(pemString: pemRepresentation)

                switch pem.type {
                case "EC PRIVATE KEY":
                    let parsed = try ASN1.SEC1PrivateKey(asn1Encoded: Array(pem.derBytes))
                    self = try .init(rawRepresentation: parsed.privateKey)
                case "PRIVATE KEY":
                    let parsed = try ASN1.PKCS8PrivateKey(asn1Encoded: Array(pem.derBytes))
                    self = try .init(rawRepresentation: parsed.privateKey.privateKey)
                default:
                    throw CryptoKitASN1Error.invalidPEMDocument
                }
            }
#endif

            /// Creates a P-384 private key for key agreement from a Distinguished Encoding
            /// Rules (DER) encoded representation.
            ///
            /// - Parameters:
            ///   - derRepresentation: A DER-encoded representation of the key.
            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws(CryptoKitMetaError) where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)

                // We have to try to parse this twice because we have no information about what kind of key this is.
                // We try with PKCS#8 first, and then fall back to SEC.1.

                do {
                    let key = try ASN1.PKCS8PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey.privateKey)
                } catch {
                    let key = try ASN1.SEC1PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey)
                }
            }

            init(impl: NISTCurvePrivateKeyImpl<P384>) {
                self.impl = impl
            }

            /// The corresponding public key.
            public var publicKey: P384.KeyAgreement.PublicKey {
                return PublicKey(impl: impl.publicKey())
            }

            /// A data representation of the private key.
            public var rawRepresentation: Data { impl.rawRepresentation }
            
            /// An ANSI x9.63 representation of the private key.
            public var x963Representation: Data { impl.x963Representation }

            /// A Distinguished Encoding Rules (DER) encoded representation of the private key.
            public var derRepresentation: Data {
                let pkey = ASN1.PKCS8PrivateKey(algorithm: .ecdsaP384, privateKey: Array(self.rawRepresentation), publicKey: Array(self.publicKey.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(pkey)
                return Data(serializer.serializedBytes)
            }

#if !hasFeature(Embedded)
            /// A Privacy-Enhanced Mail (PEM) representation of the private key.
            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PRIVATE KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
#endif
        }
    }
}
// MARK: - P521 + Signing
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P521 {
    
    /// A mechanism used to create or verify a cryptographic signature using
    /// the NIST P-521 elliptic curve digital signature algorithm (ECDSA).
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum Signing: Sendable {

        /// A P-521 public key used to verify cryptographic signatures.
        @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
        public struct PublicKey: NISTECPublicKey, Sendable {
            var impl: NISTCurvePublicKeyImpl<P521>

            /// Creates a P-521 public key for signing from a collection of bytes.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A raw representation of the key as a collection of
            /// contiguous bytes.
            public init<D: ContiguousBytes>(rawRepresentation: D) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(rawRepresentation: rawRepresentation)
            }

            /// Creates a P-521 public key for signing from a compact
            /// representation of the key.
            ///
            /// - Parameters:
            ///   - compactRepresentation: A compact representation of the key
            /// as a collection of contiguous bytes.
            public init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(compactRepresentation: compactRepresentation)
            }

            /// Creates a P-521 public key for signing from an ANSI x9.63
            /// representation.
            ///
            /// - Parameters:
            ///   - x963Representation: An ANSI x9.63 representation of the key.
            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(x963Representation: x963Representation)
            }
            
            /// Creates a P-521 public key for signing from a compressed representation of
            /// the key.
            ///
            /// - Parameters:
            ///   - compressedRepresentation: A compressed representation of the key as a collection
            /// of contiguous bytes.
            public init<Bytes: ContiguousBytes>(compressedRepresentation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(compressedRepresentation: compressedRepresentation)
            }

#if !hasFeature(Embedded)
            /// Creates a P-521 public key for signing from a Privacy-Enhanced Mail
            /// (PEM) representation.
            ///
            /// - Parameters:
            ///   - pemRepresentation: A PEM representation of the key.
            public init(pemRepresentation: String) throws(CryptoKitMetaError) {
                let pem = try ASN1.PEMDocument(pemString: pemRepresentation)
                guard pem.type == "PUBLIC KEY" else {
                    throw CryptoKitASN1Error.invalidPEMDocument
                }
                self = try .init(derRepresentation: pem.derBytes)
            }
#endif

            /// Creates a P-521 public key for signing from a Distinguished Encoding
            /// Rules (DER) encoded representation.
            ///
            /// - Parameters:
            ///   - derRepresentation: A DER-encoded representation of the key.
            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws(CryptoKitMetaError) where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)
                let parsed = try ASN1.SubjectPublicKeyInfo(asn1Encoded: bytes)
                self = try .init(x963Representation: parsed.key)
            }

            init(impl: NISTCurvePublicKeyImpl<P521>) {
                self.impl = impl
            }

            /// A compact representation of the public key.
            public var compactRepresentation: Data? { impl.compactRepresentation }
            
            /// A full representation of the public key.
            public var rawRepresentation: Data { impl.rawRepresentation }
            
            /// An ANSI x9.63 representation of the public key.
            public var x963Representation: Data { impl.x963Representation }

            /// A compressed representation of the public key.
            public var compressedRepresentation: Data { impl.compressedRepresentation }
            
            /// A Distinguished Encoding Rules (DER) encoded representation of the public key.
            public var derRepresentation: Data {
                let spki = ASN1.SubjectPublicKeyInfo(algorithmIdentifier: .ecdsaP521, key: Array(self.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(spki)
                return Data(serializer.serializedBytes)
            }

#if !hasFeature(Embedded)
            /// A Privacy-Enhanced Mail (PEM) representation of the public key.
            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PUBLIC KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
#endif
        }

        /// A P-521 private key used to create cryptographic signatures.
        @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
        public struct PrivateKey: NISTECPrivateKey, Sendable {
            let impl: NISTCurvePrivateKeyImpl<P521>

            /// Creates a random P-521 private key for signing.
            ///
            /// Keys that use a compact point encoding enable shorter public keys, but aren’t
            /// compliant with FIPS certification. If your app requires FIPS certification,
            /// create a key with ``init(rawRepresentation:)``.
            ///
            /// - Parameters:
            ///   - compactRepresentable: A Boolean value that indicates whether CryptoKit
            /// creates the key with the structure to enable compact point encoding.
            public init(compactRepresentable: Bool = true) {
                impl = NISTCurvePrivateKeyImpl(compactRepresentable: compactRepresentable)
            }

            /// Creates a P-521 private key for signing from an ANSI x9.63
            /// representation.
            ///
            /// - Parameters:
            ///   - x963Representation: An ANSI x9.63 representation of the key.
            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePrivateKeyImpl(x963: x963Representation)
            }

            /// Creates a P-521 private key for signing from a collection of bytes.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A raw representation of the key as a collection of
            /// contiguous bytes.
            public init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePrivateKeyImpl(data: rawRepresentation)
            }

#if !hasFeature(Embedded)
            /// Creates a P-521 private key for signing from a Privacy-Enhanced Mail
            /// PEM) representation.
            ///
            /// - Parameters:
            ///   - pemRepresentation: A PEM representation of the key.
            public init(pemRepresentation: String) throws(CryptoKitMetaError) {
                let pem = try ASN1.PEMDocument(pemString: pemRepresentation)

                switch pem.type {
                case "EC PRIVATE KEY":
                    let parsed = try ASN1.SEC1PrivateKey(asn1Encoded: Array(pem.derBytes))
                    self = try .init(rawRepresentation: parsed.privateKey)
                case "PRIVATE KEY":
                    let parsed = try ASN1.PKCS8PrivateKey(asn1Encoded: Array(pem.derBytes))
                    self = try .init(rawRepresentation: parsed.privateKey.privateKey)
                default:
                    throw CryptoKitASN1Error.invalidPEMDocument
                }
            }
#endif

            /// Creates a P-521 private key for signing from a Distinguished Encoding
            /// Rules (DER) encoded representation.
            ///
            /// - Parameters:
            ///   - derRepresentation: A DER-encoded representation of the key.
            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws(CryptoKitMetaError) where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)

                // We have to try to parse this twice because we have no information about what kind of key this is.
                // We try with PKCS#8 first, and then fall back to SEC.1.

                do {
                    let key = try ASN1.PKCS8PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey.privateKey)
                } catch {
                    let key = try ASN1.SEC1PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey)
                }
            }

            init(impl: NISTCurvePrivateKeyImpl<P521>) {
                self.impl = impl
            }

            /// The corresponding public key.
            public var publicKey: P521.Signing.PublicKey {
                return PublicKey(impl: impl.publicKey())
            }

            /// A data representation of the private key.
            public var rawRepresentation: Data { impl.rawRepresentation }
            
            /// An ANSI x9.63 representation of the private key.
            public var x963Representation: Data { impl.x963Representation }

            /// A Distinguished Encoding Rules (DER) encoded representation of the private key.
            public var derRepresentation: Data {
                let pkey = ASN1.PKCS8PrivateKey(algorithm: .ecdsaP521, privateKey: Array(self.rawRepresentation), publicKey: Array(self.publicKey.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(pkey)
                return Data(serializer.serializedBytes)
            }

#if !hasFeature(Embedded)
            /// A Privacy-Enhanced Mail (PEM) representation of the private key.
            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PRIVATE KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
#endif
        }
    }
}
// MARK: - P521 + KeyAgreement
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P521 {
    
    /// A mechanism used to create a shared secret between two users by
    /// performing NIST P-521 elliptic curve Diffie Hellman (ECDH) key
    /// exchange.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public enum KeyAgreement: Sendable {

        /// A P-521 public key used for key agreement.
        @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
        public struct PublicKey: NISTECPublicKey, Sendable {
            var impl: NISTCurvePublicKeyImpl<P521>

            /// Creates a P-521 public key for key agreement from a collection of bytes.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A raw representation of the key as a collection of
            /// contiguous bytes.
            public init<D: ContiguousBytes>(rawRepresentation: D) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(rawRepresentation: rawRepresentation)
            }

            /// Creates a P-521 public key for key agreement from a compact
            /// representation of the key.
            ///
            /// - Parameters:
            ///   - compactRepresentation: A compact representation of the key
            /// as a collection of contiguous bytes.
            public init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(compactRepresentation: compactRepresentation)
            }

            /// Creates a P-521 public key for key agreement from an ANSI x9.63
            /// representation.
            ///
            /// - Parameters:
            ///   - x963Representation: An ANSI x9.63 representation of the key.
            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(x963Representation: x963Representation)
            }
            
            /// Creates a P-521 public key for key agreement from a compressed representation of
            /// the key.
            ///
            /// - Parameters:
            ///   - compressedRepresentation: A compressed representation of the key as a collection
            /// of contiguous bytes.
            public init<Bytes: ContiguousBytes>(compressedRepresentation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePublicKeyImpl(compressedRepresentation: compressedRepresentation)
            }

#if !hasFeature(Embedded)
            /// Creates a P-521 public key for key agreement from a Privacy-Enhanced Mail
            /// (PEM) representation.
            ///
            /// - Parameters:
            ///   - pemRepresentation: A PEM representation of the key.
            public init(pemRepresentation: String) throws(CryptoKitMetaError) {
                let pem = try ASN1.PEMDocument(pemString: pemRepresentation)
                guard pem.type == "PUBLIC KEY" else {
                    throw CryptoKitASN1Error.invalidPEMDocument
                }
                self = try .init(derRepresentation: pem.derBytes)
            }
#endif

            /// Creates a P-521 public key for key agreement from a Distinguished Encoding
            /// Rules (DER) encoded representation.
            ///
            /// - Parameters:
            ///   - derRepresentation: A DER-encoded representation of the key.
            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws(CryptoKitMetaError) where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)
                let parsed = try ASN1.SubjectPublicKeyInfo(asn1Encoded: bytes)
                self = try .init(x963Representation: parsed.key)
            }

            init(impl: NISTCurvePublicKeyImpl<P521>) {
                self.impl = impl
            }

            /// A compact representation of the public key.
            public var compactRepresentation: Data? { impl.compactRepresentation }
            
            /// A full representation of the public key.
            public var rawRepresentation: Data { impl.rawRepresentation }
            
            /// An ANSI x9.63 representation of the public key.
            public var x963Representation: Data { impl.x963Representation }

            /// A compressed representation of the public key.
            public var compressedRepresentation: Data { impl.compressedRepresentation }
            
            /// A Distinguished Encoding Rules (DER) encoded representation of the public key.
            public var derRepresentation: Data {
                let spki = ASN1.SubjectPublicKeyInfo(algorithmIdentifier: .ecdsaP521, key: Array(self.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(spki)
                return Data(serializer.serializedBytes)
            }

#if !hasFeature(Embedded)
            /// A Privacy-Enhanced Mail (PEM) representation of the public key.
            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PUBLIC KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
#endif
        }

        /// A P-521 private key used for key agreement.
        @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
        public struct PrivateKey: NISTECPrivateKey, Sendable {
            let impl: NISTCurvePrivateKeyImpl<P521>

            /// Creates a random P-521 private key for key agreement.
            ///
            /// Keys that use a compact point encoding enable shorter public keys, but aren’t
            /// compliant with FIPS certification. If your app requires FIPS certification,
            /// create a key with ``init(rawRepresentation:)``.
            ///
            /// - Parameters:
            ///   - compactRepresentable: A Boolean value that indicates whether CryptoKit
            /// creates the key with the structure to enable compact point encoding.
            public init(compactRepresentable: Bool = true) {
                impl = NISTCurvePrivateKeyImpl(compactRepresentable: compactRepresentable)
            }

            /// Creates a P-521 private key for key agreement from an ANSI x9.63
            /// representation.
            ///
            /// - Parameters:
            ///   - x963Representation: An ANSI x9.63 representation of the key.
            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePrivateKeyImpl(x963: x963Representation)
            }

            /// Creates a P-521 private key for key agreement from a collection of bytes.
            ///
            /// - Parameters:
            ///   - rawRepresentation: A raw representation of the key as a collection of
            /// contiguous bytes.
            public init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws(CryptoKitMetaError) {
                impl = try NISTCurvePrivateKeyImpl(data: rawRepresentation)
            }

#if !hasFeature(Embedded)
            /// Creates a P-521 private key for key agreement from a Privacy-Enhanced Mail
            /// PEM) representation.
            ///
            /// - Parameters:
            ///   - pemRepresentation: A PEM representation of the key.
            public init(pemRepresentation: String) throws(CryptoKitMetaError) {
                let pem = try ASN1.PEMDocument(pemString: pemRepresentation)

                switch pem.type {
                case "EC PRIVATE KEY":
                    let parsed = try ASN1.SEC1PrivateKey(asn1Encoded: Array(pem.derBytes))
                    self = try .init(rawRepresentation: parsed.privateKey)
                case "PRIVATE KEY":
                    let parsed = try ASN1.PKCS8PrivateKey(asn1Encoded: Array(pem.derBytes))
                    self = try .init(rawRepresentation: parsed.privateKey.privateKey)
                default:
                    throw CryptoKitASN1Error.invalidPEMDocument
                }
            }
#endif

            /// Creates a P-521 private key for key agreement from a Distinguished Encoding
            /// Rules (DER) encoded representation.
            ///
            /// - Parameters:
            ///   - derRepresentation: A DER-encoded representation of the key.
            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws(CryptoKitMetaError) where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)

                // We have to try to parse this twice because we have no information about what kind of key this is.
                // We try with PKCS#8 first, and then fall back to SEC.1.

                do {
                    let key = try ASN1.PKCS8PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey.privateKey)
                } catch {
                    let key = try ASN1.SEC1PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey)
                }
            }

            init(impl: NISTCurvePrivateKeyImpl<P521>) {
                self.impl = impl
            }

            /// The corresponding public key.
            public var publicKey: P521.KeyAgreement.PublicKey {
                return PublicKey(impl: impl.publicKey())
            }

            /// A data representation of the private key.
            public var rawRepresentation: Data { impl.rawRepresentation }
            
            /// An ANSI x9.63 representation of the private key.
            public var x963Representation: Data { impl.x963Representation }

            /// A Distinguished Encoding Rules (DER) encoded representation of the private key.
            public var derRepresentation: Data {
                let pkey = ASN1.PKCS8PrivateKey(algorithm: .ecdsaP521, privateKey: Array(self.rawRepresentation), publicKey: Array(self.publicKey.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(pkey)
                return Data(serializer.serializedBytes)
            }

#if !hasFeature(Embedded)
            /// A Privacy-Enhanced Mail (PEM) representation of the private key.
            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PRIVATE KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
#endif
        }
    }
}

// MARK: - P256 + DH
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P256.KeyAgreement.PrivateKey: DiffieHellmanKeyAgreement {
    /// Computes a shared secret with the provided public key from another party.
    ///
    /// - Parameters:
    ///   - publicKeyShare: The public key from another party to be combined with the private
    /// key from this user to create the shared secret.
    /// - Returns: The computed shared secret.
    public func sharedSecretFromKeyAgreement(with publicKeyShare: P256.KeyAgreement.PublicKey) throws(CryptoKitMetaError) -> SharedSecret {
        #if (!CRYPTO_IN_SWIFTPM_FORCE_BUILD_API) || CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
        return try self.coreCryptoSharedSecretFromKeyAgreement(with: publicKeyShare)
        #else
        return try self.openSSLSharedSecretFromKeyAgreement(with: publicKeyShare)
        #endif
    }
}
// MARK: - P384 + DH
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P384.KeyAgreement.PrivateKey: DiffieHellmanKeyAgreement {
    /// Computes a shared secret with the provided public key from another party.
    ///
    /// - Parameters:
    ///   - publicKeyShare: The public key from another party to be combined with the private
    /// key from this user to create the shared secret.
    /// - Returns: The computed shared secret.
    public func sharedSecretFromKeyAgreement(with publicKeyShare: P384.KeyAgreement.PublicKey) throws(CryptoKitMetaError) -> SharedSecret {
        #if (!CRYPTO_IN_SWIFTPM_FORCE_BUILD_API) || CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
        return try self.coreCryptoSharedSecretFromKeyAgreement(with: publicKeyShare)
        #else
        return try self.openSSLSharedSecretFromKeyAgreement(with: publicKeyShare)
        #endif
    }
}
// MARK: - P521 + DH
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P521.KeyAgreement.PrivateKey: DiffieHellmanKeyAgreement {
    /// Computes a shared secret with the provided public key from another party.
    ///
    /// - Parameters:
    ///   - publicKeyShare: The public key from another party to be combined with the private
    /// key from this user to create the shared secret.
    /// - Returns: The computed shared secret.
    public func sharedSecretFromKeyAgreement(with publicKeyShare: P521.KeyAgreement.PublicKey) throws(CryptoKitMetaError) -> SharedSecret {
        #if (!CRYPTO_IN_SWIFTPM_FORCE_BUILD_API) || CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
        return try self.coreCryptoSharedSecretFromKeyAgreement(with: publicKeyShare)
        #else
        return try self.openSSLSharedSecretFromKeyAgreement(with: publicKeyShare)
        #endif
    }
}
#endif // Linux or !SwiftPM
