//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
typealias NISTCurvePublicKeyImpl = CoreCryptoNISTCurvePublicKeyImpl
typealias NISTCurvePrivateKeyImpl = CoreCryptoNISTCurvePrivateKeyImpl
#else
typealias NISTCurvePublicKeyImpl = OpenSSLNISTCurvePublicKeyImpl
typealias NISTCurvePrivateKeyImpl = OpenSSLNISTCurvePrivateKeyImpl
#endif

import Foundation

// MARK: - Generated file, do NOT edit
// any edits of this file WILL be overwritten and thus discarded
// see section `gyb` in `README` for details.

// MARK: - P256 + Signing
extension P256 {
    public enum Signing {
    
        public struct PublicKey: NISTECPublicKey {
            var impl: NISTCurvePublicKeyImpl<P256.CurveDetails>

            public init<D: ContiguousBytes>(rawRepresentation: D) throws {
                impl = try NISTCurvePublicKeyImpl(rawRepresentation: rawRepresentation)
            }

            public init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(compactRepresentation: compactRepresentation)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(x963Representation: x963Representation)
            }

            public init(pemRepresentation: String) throws {
                let pem = try ASN1.PEMDocument(pemString: pemRepresentation)
                guard pem.type == "PUBLIC KEY" else {
                    throw CryptoKitASN1Error.invalidPEMDocument
                }
                self = try .init(derRepresentation: pem.derBytes)
            }

            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)
                let parsed = try ASN1.SubjectPublicKeyInfo(asn1Encoded: bytes)
                self = try .init(x963Representation: parsed.key)
            }

            init(impl: NISTCurvePublicKeyImpl<P256.CurveDetails>) {
                self.impl = impl
            }

            public var compactRepresentation: Data? { impl.compactRepresentation }
            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }

            public var derRepresentation: Data {
                let spki = ASN1.SubjectPublicKeyInfo(algorithmIdentifier: .ecdsaP256, key: Array(self.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(spki)
                return Data(serializer.serializedBytes)
            }

            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PUBLIC KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
        }

        public struct PrivateKey: NISTECPrivateKey {
            let impl: NISTCurvePrivateKeyImpl<P256.CurveDetails>

            public init(compactRepresentable: Bool = true) {
                impl = NISTCurvePrivateKeyImpl(compactRepresentable: compactRepresentable)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(x963: x963Representation)
            }

            public init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(data: rawRepresentation)
            }

            public init(pemRepresentation: String) throws {
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

            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)

                // We have to try to parse this twice because we have no informaton about what kind of key this is.
                // We try with PKCS#8 first, and then fall back to SEC.1.

                do {
                    let key = try ASN1.PKCS8PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey.privateKey)
                } catch {
                    let key = try ASN1.SEC1PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey)
                }
            }

            init(impl: NISTCurvePrivateKeyImpl<P256.CurveDetails>) {
                self.impl = impl
            }

            public var publicKey: P256.Signing.PublicKey {
                return PublicKey(impl: impl.publicKey())
            }

            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }

            public var derRepresentation: Data {
                let pkey = ASN1.PKCS8PrivateKey(algorithm: .ecdsaP256, privateKey: Array(self.rawRepresentation), publicKey: Array(self.publicKey.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(pkey)
                return Data(serializer.serializedBytes)
            }

            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PRIVATE KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
        }
    }
}
// MARK: - P256 + KeyAgreement
extension P256 {
    public enum KeyAgreement {
    
        public struct PublicKey: NISTECPublicKey {
            var impl: NISTCurvePublicKeyImpl<P256.CurveDetails>

            public init<D: ContiguousBytes>(rawRepresentation: D) throws {
                impl = try NISTCurvePublicKeyImpl(rawRepresentation: rawRepresentation)
            }

            public init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(compactRepresentation: compactRepresentation)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(x963Representation: x963Representation)
            }

            public init(pemRepresentation: String) throws {
                let pem = try ASN1.PEMDocument(pemString: pemRepresentation)
                guard pem.type == "PUBLIC KEY" else {
                    throw CryptoKitASN1Error.invalidPEMDocument
                }
                self = try .init(derRepresentation: pem.derBytes)
            }

            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)
                let parsed = try ASN1.SubjectPublicKeyInfo(asn1Encoded: bytes)
                self = try .init(x963Representation: parsed.key)
            }

            init(impl: NISTCurvePublicKeyImpl<P256.CurveDetails>) {
                self.impl = impl
            }

            public var compactRepresentation: Data? { impl.compactRepresentation }
            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }

            public var derRepresentation: Data {
                let spki = ASN1.SubjectPublicKeyInfo(algorithmIdentifier: .ecdsaP256, key: Array(self.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(spki)
                return Data(serializer.serializedBytes)
            }

            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PUBLIC KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
        }

        public struct PrivateKey: NISTECPrivateKey {
            let impl: NISTCurvePrivateKeyImpl<P256.CurveDetails>

            public init(compactRepresentable: Bool = true) {
                impl = NISTCurvePrivateKeyImpl(compactRepresentable: compactRepresentable)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(x963: x963Representation)
            }

            public init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(data: rawRepresentation)
            }

            public init(pemRepresentation: String) throws {
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

            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)

                // We have to try to parse this twice because we have no informaton about what kind of key this is.
                // We try with PKCS#8 first, and then fall back to SEC.1.

                do {
                    let key = try ASN1.PKCS8PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey.privateKey)
                } catch {
                    let key = try ASN1.SEC1PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey)
                }
            }

            init(impl: NISTCurvePrivateKeyImpl<P256.CurveDetails>) {
                self.impl = impl
            }

            public var publicKey: P256.KeyAgreement.PublicKey {
                return PublicKey(impl: impl.publicKey())
            }

            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }

            public var derRepresentation: Data {
                let pkey = ASN1.PKCS8PrivateKey(algorithm: .ecdsaP256, privateKey: Array(self.rawRepresentation), publicKey: Array(self.publicKey.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(pkey)
                return Data(serializer.serializedBytes)
            }

            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PRIVATE KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
        }
    }
}
// MARK: - P384 + Signing
extension P384 {
    public enum Signing {
    
        public struct PublicKey: NISTECPublicKey {
            var impl: NISTCurvePublicKeyImpl<P384.CurveDetails>

            public init<D: ContiguousBytes>(rawRepresentation: D) throws {
                impl = try NISTCurvePublicKeyImpl(rawRepresentation: rawRepresentation)
            }

            public init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(compactRepresentation: compactRepresentation)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(x963Representation: x963Representation)
            }

            public init(pemRepresentation: String) throws {
                let pem = try ASN1.PEMDocument(pemString: pemRepresentation)
                guard pem.type == "PUBLIC KEY" else {
                    throw CryptoKitASN1Error.invalidPEMDocument
                }
                self = try .init(derRepresentation: pem.derBytes)
            }

            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)
                let parsed = try ASN1.SubjectPublicKeyInfo(asn1Encoded: bytes)
                self = try .init(x963Representation: parsed.key)
            }

            init(impl: NISTCurvePublicKeyImpl<P384.CurveDetails>) {
                self.impl = impl
            }

            public var compactRepresentation: Data? { impl.compactRepresentation }
            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }

            public var derRepresentation: Data {
                let spki = ASN1.SubjectPublicKeyInfo(algorithmIdentifier: .ecdsaP384, key: Array(self.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(spki)
                return Data(serializer.serializedBytes)
            }

            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PUBLIC KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
        }

        public struct PrivateKey: NISTECPrivateKey {
            let impl: NISTCurvePrivateKeyImpl<P384.CurveDetails>

            public init(compactRepresentable: Bool = true) {
                impl = NISTCurvePrivateKeyImpl(compactRepresentable: compactRepresentable)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(x963: x963Representation)
            }

            public init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(data: rawRepresentation)
            }

            public init(pemRepresentation: String) throws {
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

            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)

                // We have to try to parse this twice because we have no informaton about what kind of key this is.
                // We try with PKCS#8 first, and then fall back to SEC.1.

                do {
                    let key = try ASN1.PKCS8PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey.privateKey)
                } catch {
                    let key = try ASN1.SEC1PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey)
                }
            }

            init(impl: NISTCurvePrivateKeyImpl<P384.CurveDetails>) {
                self.impl = impl
            }

            public var publicKey: P384.Signing.PublicKey {
                return PublicKey(impl: impl.publicKey())
            }

            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }

            public var derRepresentation: Data {
                let pkey = ASN1.PKCS8PrivateKey(algorithm: .ecdsaP384, privateKey: Array(self.rawRepresentation), publicKey: Array(self.publicKey.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(pkey)
                return Data(serializer.serializedBytes)
            }

            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PRIVATE KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
        }
    }
}
// MARK: - P384 + KeyAgreement
extension P384 {
    public enum KeyAgreement {
    
        public struct PublicKey: NISTECPublicKey {
            var impl: NISTCurvePublicKeyImpl<P384.CurveDetails>

            public init<D: ContiguousBytes>(rawRepresentation: D) throws {
                impl = try NISTCurvePublicKeyImpl(rawRepresentation: rawRepresentation)
            }

            public init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(compactRepresentation: compactRepresentation)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(x963Representation: x963Representation)
            }

            public init(pemRepresentation: String) throws {
                let pem = try ASN1.PEMDocument(pemString: pemRepresentation)
                guard pem.type == "PUBLIC KEY" else {
                    throw CryptoKitASN1Error.invalidPEMDocument
                }
                self = try .init(derRepresentation: pem.derBytes)
            }

            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)
                let parsed = try ASN1.SubjectPublicKeyInfo(asn1Encoded: bytes)
                self = try .init(x963Representation: parsed.key)
            }

            init(impl: NISTCurvePublicKeyImpl<P384.CurveDetails>) {
                self.impl = impl
            }

            public var compactRepresentation: Data? { impl.compactRepresentation }
            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }

            public var derRepresentation: Data {
                let spki = ASN1.SubjectPublicKeyInfo(algorithmIdentifier: .ecdsaP384, key: Array(self.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(spki)
                return Data(serializer.serializedBytes)
            }

            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PUBLIC KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
        }

        public struct PrivateKey: NISTECPrivateKey {
            let impl: NISTCurvePrivateKeyImpl<P384.CurveDetails>

            public init(compactRepresentable: Bool = true) {
                impl = NISTCurvePrivateKeyImpl(compactRepresentable: compactRepresentable)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(x963: x963Representation)
            }

            public init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(data: rawRepresentation)
            }

            public init(pemRepresentation: String) throws {
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

            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)

                // We have to try to parse this twice because we have no informaton about what kind of key this is.
                // We try with PKCS#8 first, and then fall back to SEC.1.

                do {
                    let key = try ASN1.PKCS8PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey.privateKey)
                } catch {
                    let key = try ASN1.SEC1PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey)
                }
            }

            init(impl: NISTCurvePrivateKeyImpl<P384.CurveDetails>) {
                self.impl = impl
            }

            public var publicKey: P384.KeyAgreement.PublicKey {
                return PublicKey(impl: impl.publicKey())
            }

            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }

            public var derRepresentation: Data {
                let pkey = ASN1.PKCS8PrivateKey(algorithm: .ecdsaP384, privateKey: Array(self.rawRepresentation), publicKey: Array(self.publicKey.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(pkey)
                return Data(serializer.serializedBytes)
            }

            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PRIVATE KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
        }
    }
}
// MARK: - P521 + Signing
extension P521 {
    public enum Signing {
    
        public struct PublicKey: NISTECPublicKey {
            var impl: NISTCurvePublicKeyImpl<P521.CurveDetails>

            public init<D: ContiguousBytes>(rawRepresentation: D) throws {
                impl = try NISTCurvePublicKeyImpl(rawRepresentation: rawRepresentation)
            }

            public init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(compactRepresentation: compactRepresentation)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(x963Representation: x963Representation)
            }

            public init(pemRepresentation: String) throws {
                let pem = try ASN1.PEMDocument(pemString: pemRepresentation)
                guard pem.type == "PUBLIC KEY" else {
                    throw CryptoKitASN1Error.invalidPEMDocument
                }
                self = try .init(derRepresentation: pem.derBytes)
            }

            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)
                let parsed = try ASN1.SubjectPublicKeyInfo(asn1Encoded: bytes)
                self = try .init(x963Representation: parsed.key)
            }

            init(impl: NISTCurvePublicKeyImpl<P521.CurveDetails>) {
                self.impl = impl
            }

            public var compactRepresentation: Data? { impl.compactRepresentation }
            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }

            public var derRepresentation: Data {
                let spki = ASN1.SubjectPublicKeyInfo(algorithmIdentifier: .ecdsaP521, key: Array(self.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(spki)
                return Data(serializer.serializedBytes)
            }

            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PUBLIC KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
        }

        public struct PrivateKey: NISTECPrivateKey {
            let impl: NISTCurvePrivateKeyImpl<P521.CurveDetails>

            public init(compactRepresentable: Bool = true) {
                impl = NISTCurvePrivateKeyImpl(compactRepresentable: compactRepresentable)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(x963: x963Representation)
            }

            public init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(data: rawRepresentation)
            }

            public init(pemRepresentation: String) throws {
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

            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)

                // We have to try to parse this twice because we have no informaton about what kind of key this is.
                // We try with PKCS#8 first, and then fall back to SEC.1.

                do {
                    let key = try ASN1.PKCS8PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey.privateKey)
                } catch {
                    let key = try ASN1.SEC1PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey)
                }
            }

            init(impl: NISTCurvePrivateKeyImpl<P521.CurveDetails>) {
                self.impl = impl
            }

            public var publicKey: P521.Signing.PublicKey {
                return PublicKey(impl: impl.publicKey())
            }

            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }

            public var derRepresentation: Data {
                let pkey = ASN1.PKCS8PrivateKey(algorithm: .ecdsaP521, privateKey: Array(self.rawRepresentation), publicKey: Array(self.publicKey.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(pkey)
                return Data(serializer.serializedBytes)
            }

            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PRIVATE KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
        }
    }
}
// MARK: - P521 + KeyAgreement
extension P521 {
    public enum KeyAgreement {
    
        public struct PublicKey: NISTECPublicKey {
            var impl: NISTCurvePublicKeyImpl<P521.CurveDetails>

            public init<D: ContiguousBytes>(rawRepresentation: D) throws {
                impl = try NISTCurvePublicKeyImpl(rawRepresentation: rawRepresentation)
            }

            public init<Bytes: ContiguousBytes>(compactRepresentation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(compactRepresentation: compactRepresentation)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePublicKeyImpl(x963Representation: x963Representation)
            }

            public init(pemRepresentation: String) throws {
                let pem = try ASN1.PEMDocument(pemString: pemRepresentation)
                guard pem.type == "PUBLIC KEY" else {
                    throw CryptoKitASN1Error.invalidPEMDocument
                }
                self = try .init(derRepresentation: pem.derBytes)
            }

            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)
                let parsed = try ASN1.SubjectPublicKeyInfo(asn1Encoded: bytes)
                self = try .init(x963Representation: parsed.key)
            }

            init(impl: NISTCurvePublicKeyImpl<P521.CurveDetails>) {
                self.impl = impl
            }

            public var compactRepresentation: Data? { impl.compactRepresentation }
            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }

            public var derRepresentation: Data {
                let spki = ASN1.SubjectPublicKeyInfo(algorithmIdentifier: .ecdsaP521, key: Array(self.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(spki)
                return Data(serializer.serializedBytes)
            }

            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PUBLIC KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
        }

        public struct PrivateKey: NISTECPrivateKey {
            let impl: NISTCurvePrivateKeyImpl<P521.CurveDetails>

            public init(compactRepresentable: Bool = true) {
                impl = NISTCurvePrivateKeyImpl(compactRepresentable: compactRepresentable)
            }

            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(x963: x963Representation)
            }

            public init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws {
                impl = try NISTCurvePrivateKeyImpl(data: rawRepresentation)
            }

            public init(pemRepresentation: String) throws {
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

            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws where Bytes.Element == UInt8 {
                let bytes = Array(derRepresentation)

                // We have to try to parse this twice because we have no informaton about what kind of key this is.
                // We try with PKCS#8 first, and then fall back to SEC.1.

                do {
                    let key = try ASN1.PKCS8PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey.privateKey)
                } catch {
                    let key = try ASN1.SEC1PrivateKey(asn1Encoded: bytes)
                    self = try .init(rawRepresentation: key.privateKey)
                }
            }

            init(impl: NISTCurvePrivateKeyImpl<P521.CurveDetails>) {
                self.impl = impl
            }

            public var publicKey: P521.KeyAgreement.PublicKey {
                return PublicKey(impl: impl.publicKey())
            }

            public var rawRepresentation: Data { impl.rawRepresentation }
            public var x963Representation: Data { impl.x963Representation }

            public var derRepresentation: Data {
                let pkey = ASN1.PKCS8PrivateKey(algorithm: .ecdsaP521, privateKey: Array(self.rawRepresentation), publicKey: Array(self.publicKey.x963Representation))
                var serializer = ASN1.Serializer()

                // Serializing these keys can't throw
                try! serializer.serialize(pkey)
                return Data(serializer.serializedBytes)
            }

            public var pemRepresentation: String {
                let pemDocument = ASN1.PEMDocument(type: "PRIVATE KEY", derBytes: self.derRepresentation)
                return pemDocument.pemString
            }
        }
    }
}

// MARK: - P256 + DH
extension P256.KeyAgreement.PrivateKey: DiffieHellmanKeyAgreement {
    /// Performs a key agreement with provided public key share.
    ///
    /// - Parameter publicKeyShare: The public key to perform the ECDH with.
    /// - Returns: Returns a shared secret
    /// - Throws: An error occurred while computing the shared secret
    public func sharedSecretFromKeyAgreement(with publicKeyShare: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        #if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        return try self.coreCryptoSharedSecretFromKeyAgreement(with: publicKeyShare)
        #else
        return try self.openSSLSharedSecretFromKeyAgreement(with: publicKeyShare)
        #endif
    }
}
// MARK: - P384 + DH
extension P384.KeyAgreement.PrivateKey: DiffieHellmanKeyAgreement {
    /// Performs a key agreement with provided public key share.
    ///
    /// - Parameter publicKeyShare: The public key to perform the ECDH with.
    /// - Returns: Returns a shared secret
    /// - Throws: An error occurred while computing the shared secret
    public func sharedSecretFromKeyAgreement(with publicKeyShare: P384.KeyAgreement.PublicKey) throws -> SharedSecret {
        #if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        return try self.coreCryptoSharedSecretFromKeyAgreement(with: publicKeyShare)
        #else
        return try self.openSSLSharedSecretFromKeyAgreement(with: publicKeyShare)
        #endif
    }
}
// MARK: - P521 + DH
extension P521.KeyAgreement.PrivateKey: DiffieHellmanKeyAgreement {
    /// Performs a key agreement with provided public key share.
    ///
    /// - Parameter publicKeyShare: The public key to perform the ECDH with.
    /// - Returns: Returns a shared secret
    /// - Throws: An error occurred while computing the shared secret
    public func sharedSecretFromKeyAgreement(with publicKeyShare: P521.KeyAgreement.PublicKey) throws -> SharedSecret {
        #if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        return try self.coreCryptoSharedSecretFromKeyAgreement(with: publicKeyShare)
        #else
        return try self.openSSLSharedSecretFromKeyAgreement(with: publicKeyShare)
        #endif
    }
}
#endif // Linux or !SwiftPM
