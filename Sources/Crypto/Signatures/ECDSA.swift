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
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
import Foundation
// MARK: - Generated file, do NOT edit
// any edits of this file WILL be overwritten and thus discarded
// see section `gyb` in `README` for details.

protocol NISTECDSASignature {
    init<D: DataProtocol>(rawRepresentation: D) throws
    init<D: DataProtocol>(derRepresentation: D) throws
    var derRepresentation: Data { get }
    var rawRepresentation: Data { get }
}

protocol NISTSigning {
    associatedtype PublicKey: NISTECPublicKey & DataValidator & DigestValidator
    associatedtype PrivateKey: NISTECPrivateKey & Signer
    associatedtype ECDSASignature: NISTECDSASignature
}

// MARK: - P256 + Signing
extension P256.Signing {

    /// A P-256 elliptic curve digital signature algorithm (ECDSA) signature.
    public struct ECDSASignature: ContiguousBytes, NISTECDSASignature {
        
        /// A raw data representation of a P-256 digital signature.
        public var rawRepresentation: Data

        /// Creates a P-256 digital signature from a raw representation.
        ///
        /// - Parameters:
        ///   - rawRepresentation: A raw representation of the signature as a
        /// collection of contiguous bytes.
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            guard rawRepresentation.count == 2 * P256.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.rawRepresentation = Data(rawRepresentation)
        }
        
        internal init(_ dataRepresentation: Data) throws {
            guard dataRepresentation.count == 2 * P256.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.rawRepresentation = dataRepresentation
        }

        var composite: (r: Data, s: Data) {
            let combined = rawRepresentation
            assert(combined.count % 2 == 0)
            let half = combined.count / 2
            return (combined.prefix(upTo: half), combined.suffix(from: half))
        }

        /// Creates a P-256 digital signature from a Distinguished Encoding
        /// Rules (DER) encoded representation.
        ///
        /// - Parameters:
        ///   - derRepresentation: The DER-encoded representation of the
        /// signature.
        public init<D: DataProtocol>(derRepresentation: D) throws {
            #if os(iOS) && (arch(arm) || arch(i386))
            fatalError("Unsupported architecture")
            #else
            let parsed = try ASN1.parse(Array(derRepresentation))
            let signature = try ASN1.ECDSASignature<ArraySlice<UInt8>>(asn1Encoded: parsed)

            let coordinateByteCount = P256.coordinateByteCount

            guard signature.r.count <= coordinateByteCount && signature.s.count <= coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            // r and s must be padded out to the coordinate byte count.
            var raw = Data()
            raw.reserveCapacity(2 * P256.coordinateByteCount)

            raw.append(contentsOf: repeatElement(0, count: P256.coordinateByteCount - signature.r.count))
            raw.append(contentsOf: signature.r)
            raw.append(contentsOf: repeatElement(0, count: P256.coordinateByteCount - signature.s.count))
            raw.append(contentsOf: signature.s)

            self.rawRepresentation = raw
            #endif
        }

        /// Invokes the given closure with a buffer pointer covering the raw
        /// bytes of the signature.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try self.rawRepresentation.withUnsafeBytes(body)
        }

        /// A Distinguished Encoding Rules (DER) encoded representation of a
        /// P-256 digital signature.
        public var derRepresentation: Data {
            #if os(iOS) && (arch(arm) || arch(i386))
            fatalError("Unsupported architecture")
            #else
            let raw = rawRepresentation
            let half = raw.count / 2
            let r = Array(raw.prefix(upTo: half))[...]
            let s = Array(raw.suffix(from: half))[...]

            let sig = ASN1.ECDSASignature(r: r, s: s)
            var serializer = ASN1.Serializer()
            try! serializer.serialize(sig)
            return Data(serializer.serializedBytes)
            #endif
        }
    }
}

extension P256.Signing: NISTSigning {}

// MARK: - P256 + PrivateKey
extension P256.Signing.PrivateKey: DigestSigner {
    /// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA)
    /// signature of the digest you provide over the P-256 elliptic curve.
    ///
    /// - Parameters:
    ///   - digest: The digest of the data to sign.
    /// - Returns: The signature corresponding to the digest. The signing
    /// algorithm employs randomization to generate a different signature on
    /// every call, even for the same data and key.
    public func signature<D: Digest>(for digest: D) throws -> P256.Signing.ECDSASignature {
        #if !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        return try self.coreCryptoSignature(for: digest)
        #else
        return try self.openSSLSignature(for: digest)
        #endif
    }
 }

extension P256.Signing.PrivateKey: Signer {
    /// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA)
    /// signature of the data you provide over the P-256 elliptic curve,
    /// using SHA-256 as the hash function.
    ///
    /// - Parameters:
    ///   - data: The data to sign.
    /// - Returns: The signature corresponding to the data. The signing
    /// algorithm employs randomization to generate a different signature on
    /// every call, even for the same data and key.
    public func signature<D: DataProtocol>(for data: D) throws -> P256.Signing.ECDSASignature {
        return try self.signature(for: SHA256.hash(data: data))
    }
}

extension P256.Signing.PublicKey: DigestValidator {
    /// Verifies an elliptic curve digital signature algorithm (ECDSA)
    /// signature on a digest over the P-256 elliptic curve.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify.
    ///   - digest: The signed digest.
    /// - Returns: A Boolean value that’s `true` if the signature is valid for
    /// the given digest; otherwise, `false`.
    public func isValidSignature<D: Digest>(_ signature: P256.Signing.ECDSASignature, for digest: D) -> Bool {
        #if !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        return self.coreCryptoIsValidSignature(signature, for: digest)
        #else
        return self.openSSLIsValidSignature(signature, for: digest)
        #endif
    }
}

extension P256.Signing.PublicKey: DataValidator {
    /// Verifies an elliptic curve digital signature algorithm (ECDSA)
    /// signature on a block of data over the P-256 elliptic curve.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify.
    ///   - data: The signed data.
    /// - Returns: A Boolean value that’s `true` if the signature is valid for
    /// the given data; otherwise, `false`.
    public func isValidSignature<D: DataProtocol>(_ signature: P256.Signing.ECDSASignature, for data: D) -> Bool {
        return self.isValidSignature(signature, for: SHA256.hash(data: data))
    }
 }

// MARK: - P384 + Signing
extension P384.Signing {

    /// A P-384 elliptic curve digital signature algorithm (ECDSA) signature.
    public struct ECDSASignature: ContiguousBytes, NISTECDSASignature {
        
        /// A raw data representation of a P-384 digital signature.
        public var rawRepresentation: Data

        /// Creates a P-384 digital signature from a raw representation.
        ///
        /// - Parameters:
        ///   - rawRepresentation: A raw representation of the signature as a
        /// collection of contiguous bytes.
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            guard rawRepresentation.count == 2 * P384.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.rawRepresentation = Data(rawRepresentation)
        }
        
        internal init(_ dataRepresentation: Data) throws {
            guard dataRepresentation.count == 2 * P384.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.rawRepresentation = dataRepresentation
        }

        var composite: (r: Data, s: Data) {
            let combined = rawRepresentation
            assert(combined.count % 2 == 0)
            let half = combined.count / 2
            return (combined.prefix(upTo: half), combined.suffix(from: half))
        }

        /// Creates a P-384 digital signature from a Distinguished Encoding
        /// Rules (DER) encoded representation.
        ///
        /// - Parameters:
        ///   - derRepresentation: The DER-encoded representation of the
        /// signature.
        public init<D: DataProtocol>(derRepresentation: D) throws {
            #if os(iOS) && (arch(arm) || arch(i386))
            fatalError("Unsupported architecture")
            #else
            let parsed = try ASN1.parse(Array(derRepresentation))
            let signature = try ASN1.ECDSASignature<ArraySlice<UInt8>>(asn1Encoded: parsed)

            let coordinateByteCount = P384.coordinateByteCount

            guard signature.r.count <= coordinateByteCount && signature.s.count <= coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            // r and s must be padded out to the coordinate byte count.
            var raw = Data()
            raw.reserveCapacity(2 * P384.coordinateByteCount)

            raw.append(contentsOf: repeatElement(0, count: P384.coordinateByteCount - signature.r.count))
            raw.append(contentsOf: signature.r)
            raw.append(contentsOf: repeatElement(0, count: P384.coordinateByteCount - signature.s.count))
            raw.append(contentsOf: signature.s)

            self.rawRepresentation = raw
            #endif
        }

        /// Invokes the given closure with a buffer pointer covering the raw
        /// bytes of the signature.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try self.rawRepresentation.withUnsafeBytes(body)
        }

        /// A Distinguished Encoding Rules (DER) encoded representation of a
        /// P-384 digital signature.
        public var derRepresentation: Data {
            #if os(iOS) && (arch(arm) || arch(i386))
            fatalError("Unsupported architecture")
            #else
            let raw = rawRepresentation
            let half = raw.count / 2
            let r = Array(raw.prefix(upTo: half))[...]
            let s = Array(raw.suffix(from: half))[...]

            let sig = ASN1.ECDSASignature(r: r, s: s)
            var serializer = ASN1.Serializer()
            try! serializer.serialize(sig)
            return Data(serializer.serializedBytes)
            #endif
        }
    }
}

extension P384.Signing: NISTSigning {}

// MARK: - P384 + PrivateKey
extension P384.Signing.PrivateKey: DigestSigner {
    /// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA)
    /// signature of the digest you provide over the P-384 elliptic curve.
    ///
    /// - Parameters:
    ///   - digest: The digest of the data to sign.
    /// - Returns: The signature corresponding to the digest. The signing
    /// algorithm employs randomization to generate a different signature on
    /// every call, even for the same data and key.
    public func signature<D: Digest>(for digest: D) throws -> P384.Signing.ECDSASignature {
        #if !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        return try self.coreCryptoSignature(for: digest)
        #else
        return try self.openSSLSignature(for: digest)
        #endif
    }
 }

extension P384.Signing.PrivateKey: Signer {
    /// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA)
    /// signature of the data you provide over the P-384 elliptic curve,
    /// using SHA-384 as the hash function.
    ///
    /// - Parameters:
    ///   - data: The data to sign.
    /// - Returns: The signature corresponding to the data. The signing
    /// algorithm employs randomization to generate a different signature on
    /// every call, even for the same data and key.
    public func signature<D: DataProtocol>(for data: D) throws -> P384.Signing.ECDSASignature {
        return try self.signature(for: SHA384.hash(data: data))
    }
}

extension P384.Signing.PublicKey: DigestValidator {
    /// Verifies an elliptic curve digital signature algorithm (ECDSA)
    /// signature on a digest over the P-384 elliptic curve.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify.
    ///   - digest: The signed digest.
    /// - Returns: A Boolean value that’s `true` if the signature is valid for
    /// the given digest; otherwise, `false`.
    public func isValidSignature<D: Digest>(_ signature: P384.Signing.ECDSASignature, for digest: D) -> Bool {
        #if !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        return self.coreCryptoIsValidSignature(signature, for: digest)
        #else
        return self.openSSLIsValidSignature(signature, for: digest)
        #endif
    }
}

extension P384.Signing.PublicKey: DataValidator {
    /// Verifies an elliptic curve digital signature algorithm (ECDSA)
    /// signature on a block of data over the P-384 elliptic curve.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify.
    ///   - data: The signed data.
    /// - Returns: A Boolean value that’s `true` if the signature is valid for
    /// the given data; otherwise, `false`.
    public func isValidSignature<D: DataProtocol>(_ signature: P384.Signing.ECDSASignature, for data: D) -> Bool {
        return self.isValidSignature(signature, for: SHA384.hash(data: data))
    }
 }

// MARK: - P521 + Signing
extension P521.Signing {

    /// A P-521 elliptic curve digital signature algorithm (ECDSA) signature.
    public struct ECDSASignature: ContiguousBytes, NISTECDSASignature {
        
        /// A raw data representation of a P-521 digital signature.
        public var rawRepresentation: Data

        /// Creates a P-521 digital signature from a raw representation.
        ///
        /// - Parameters:
        ///   - rawRepresentation: A raw representation of the signature as a
        /// collection of contiguous bytes.
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            guard rawRepresentation.count == 2 * P521.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.rawRepresentation = Data(rawRepresentation)
        }
        
        internal init(_ dataRepresentation: Data) throws {
            guard dataRepresentation.count == 2 * P521.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.rawRepresentation = dataRepresentation
        }

        var composite: (r: Data, s: Data) {
            let combined = rawRepresentation
            assert(combined.count % 2 == 0)
            let half = combined.count / 2
            return (combined.prefix(upTo: half), combined.suffix(from: half))
        }

        /// Creates a P-521 digital signature from a Distinguished Encoding
        /// Rules (DER) encoded representation.
        ///
        /// - Parameters:
        ///   - derRepresentation: The DER-encoded representation of the
        /// signature.
        public init<D: DataProtocol>(derRepresentation: D) throws {
            #if os(iOS) && (arch(arm) || arch(i386))
            fatalError("Unsupported architecture")
            #else
            let parsed = try ASN1.parse(Array(derRepresentation))
            let signature = try ASN1.ECDSASignature<ArraySlice<UInt8>>(asn1Encoded: parsed)

            let coordinateByteCount = P521.coordinateByteCount

            guard signature.r.count <= coordinateByteCount && signature.s.count <= coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            // r and s must be padded out to the coordinate byte count.
            var raw = Data()
            raw.reserveCapacity(2 * P521.coordinateByteCount)

            raw.append(contentsOf: repeatElement(0, count: P521.coordinateByteCount - signature.r.count))
            raw.append(contentsOf: signature.r)
            raw.append(contentsOf: repeatElement(0, count: P521.coordinateByteCount - signature.s.count))
            raw.append(contentsOf: signature.s)

            self.rawRepresentation = raw
            #endif
        }

        /// Invokes the given closure with a buffer pointer covering the raw
        /// bytes of the signature.
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try self.rawRepresentation.withUnsafeBytes(body)
        }

        /// A Distinguished Encoding Rules (DER) encoded representation of a
        /// P-521 digital signature.
        public var derRepresentation: Data {
            #if os(iOS) && (arch(arm) || arch(i386))
            fatalError("Unsupported architecture")
            #else
            let raw = rawRepresentation
            let half = raw.count / 2
            let r = Array(raw.prefix(upTo: half))[...]
            let s = Array(raw.suffix(from: half))[...]

            let sig = ASN1.ECDSASignature(r: r, s: s)
            var serializer = ASN1.Serializer()
            try! serializer.serialize(sig)
            return Data(serializer.serializedBytes)
            #endif
        }
    }
}

extension P521.Signing: NISTSigning {}

// MARK: - P521 + PrivateKey
extension P521.Signing.PrivateKey: DigestSigner {
    /// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA)
    /// signature of the digest you provide over the P-521 elliptic curve.
    ///
    /// - Parameters:
    ///   - digest: The digest of the data to sign.
    /// - Returns: The signature corresponding to the digest. The signing
    /// algorithm employs randomization to generate a different signature on
    /// every call, even for the same data and key.
    public func signature<D: Digest>(for digest: D) throws -> P521.Signing.ECDSASignature {
        #if !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        return try self.coreCryptoSignature(for: digest)
        #else
        return try self.openSSLSignature(for: digest)
        #endif
    }
 }

extension P521.Signing.PrivateKey: Signer {
    /// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA)
    /// signature of the data you provide over the P-521 elliptic curve,
    /// using SHA-512 as the hash function.
    ///
    /// - Parameters:
    ///   - data: The data to sign.
    /// - Returns: The signature corresponding to the data. The signing
    /// algorithm employs randomization to generate a different signature on
    /// every call, even for the same data and key.
    public func signature<D: DataProtocol>(for data: D) throws -> P521.Signing.ECDSASignature {
        return try self.signature(for: SHA512.hash(data: data))
    }
}

extension P521.Signing.PublicKey: DigestValidator {
    /// Verifies an elliptic curve digital signature algorithm (ECDSA)
    /// signature on a digest over the P-521 elliptic curve.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify.
    ///   - digest: The signed digest.
    /// - Returns: A Boolean value that’s `true` if the signature is valid for
    /// the given digest; otherwise, `false`.
    public func isValidSignature<D: Digest>(_ signature: P521.Signing.ECDSASignature, for digest: D) -> Bool {
        #if !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
        return self.coreCryptoIsValidSignature(signature, for: digest)
        #else
        return self.openSSLIsValidSignature(signature, for: digest)
        #endif
    }
}

extension P521.Signing.PublicKey: DataValidator {
    /// Verifies an elliptic curve digital signature algorithm (ECDSA)
    /// signature on a block of data over the P-521 elliptic curve.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify.
    ///   - data: The signed data.
    /// - Returns: A Boolean value that’s `true` if the signature is valid for
    /// the given data; otherwise, `false`.
    public func isValidSignature<D: DataProtocol>(_ signature: P521.Signing.ECDSASignature, for data: D) -> Bool {
        return self.isValidSignature(signature, for: SHA512.hash(data: data))
    }
 }


#endif // Linux or !SwiftPM
