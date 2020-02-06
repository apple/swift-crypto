//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
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
@_implementationOnly import CCryptoBoringSSL
import Foundation

extension Data {
    init<D: DataProtocol, Curve: OpenSSLSupportedNISTCurve>(derSignature derBytes: D, over: Curve.Type = Curve.self) throws {
        // BoringSSL requires a contiguous buffer of memory, so if we don't have one we need to create one.
        if derBytes.regions.count == 1 {
            self = try Data(contiguousDERBytes: derBytes.regions.first!, over: Curve.self)
        } else {
            let contiguousDERBytes = Array(derBytes)
            self = try Data(contiguousDERBytes: contiguousDERBytes, over: Curve.self)
        }
    }

    init<ContiguousBuffer: ContiguousBytes, Curve: OpenSSLSupportedNISTCurve>(contiguousDERBytes derBytes: ContiguousBuffer,
                                                                              over curve: Curve.Type = Curve.self) throws {
        let sig = try ECDSASignature(contiguousDERBytes: derBytes)
        self = try Data(rawSignature: sig, over: curve)
    }

    init<Curve: OpenSSLSupportedNISTCurve>(rawSignature signature: ECDSASignature, over curve: Curve.Type = Curve.self) throws {
        // We need to bring this into the raw representation, which is r || s as defined in https://tools.ietf.org/html/rfc4754.
        let (r, s) = signature.components
        let curveByteCount = Curve.coordinateByteCount

        var baseData = Data()
        baseData.reserveCapacity(curveByteCount * 2)

        try baseData.append(bytesOf: r, paddedToSize: curveByteCount)
        try baseData.append(bytesOf: s, paddedToSize: curveByteCount)

        self = baseData
    }
}

extension P256.Signing.ECDSASignature {
    init<D: DataProtocol>(openSSLDERSignature derRepresentation: D) throws {
        self.rawRepresentation = try Data(derSignature: derRepresentation, over: P256.CurveDetails.self)
    }

    var openSSLDERRepresentation: Data {
        return try! ECDSASignature(rawRepresentation: self.rawRepresentation).derBytes
    }
}

extension P256.Signing.PrivateKey {
    func openSSLSignature<D: Digest>(for digest: D) throws -> P256.Signing.ECDSASignature {
        let baseSignature = try self.impl.key.sign(digest: digest)
        return try .init(rawRepresentation: Data(rawSignature: baseSignature, over: P256.CurveDetails.self))
    }
}

extension P256.Signing.PublicKey {
    func openSSLIsValidSignature<D: Digest>(_ signature: P256.Signing.ECDSASignature, for digest: D) -> Bool {
        guard let baseSignature = try? ECDSASignature(rawRepresentation: signature.rawRepresentation) else {
            // If we can't create a signature, it's not valid.
            return false
        }

        return self.impl.key.isValidSignature(baseSignature, for: digest)
    }
}

extension P384.Signing.ECDSASignature {
    init<D: DataProtocol>(openSSLDERSignature derRepresentation: D) throws {
        self.rawRepresentation = try Data(derSignature: derRepresentation, over: P384.CurveDetails.self)
    }

    var openSSLDERRepresentation: Data {
        return try! ECDSASignature(rawRepresentation: self.rawRepresentation).derBytes
    }
}

extension P384.Signing.PrivateKey {
    func openSSLSignature<D: Digest>(for digest: D) throws -> P384.Signing.ECDSASignature {
        let baseSignature = try self.impl.key.sign(digest: digest)
        return try .init(rawRepresentation: Data(rawSignature: baseSignature, over: P384.CurveDetails.self))
    }
}

extension P384.Signing.PublicKey {
    func openSSLIsValidSignature<D: Digest>(_ signature: P384.Signing.ECDSASignature, for digest: D) -> Bool {
        guard let baseSignature = try? ECDSASignature(rawRepresentation: signature.rawRepresentation) else {
            // If we can't create a signature, it's not valid.
            return false
        }

        return self.impl.key.isValidSignature(baseSignature, for: digest)
    }
}

extension P521.Signing.ECDSASignature {
    init<D: DataProtocol>(openSSLDERSignature derRepresentation: D) throws {
        self.rawRepresentation = try Data(derSignature: derRepresentation, over: P521.CurveDetails.self)
    }

    var openSSLDERRepresentation: Data {
        return try! ECDSASignature(rawRepresentation: self.rawRepresentation).derBytes
    }
}

extension P521.Signing.PrivateKey {
    func openSSLSignature<D: Digest>(for digest: D) throws -> P521.Signing.ECDSASignature {
        let baseSignature = try self.impl.key.sign(digest: digest)
        return try .init(rawRepresentation: Data(rawSignature: baseSignature, over: P521.CurveDetails.self))
    }
}

extension P521.Signing.PublicKey {
    func openSSLIsValidSignature<D: Digest>(_ signature: P521.Signing.ECDSASignature, for digest: D) -> Bool {
        guard let baseSignature = try? ECDSASignature(rawRepresentation: signature.rawRepresentation) else {
            // If we can't create a signature, it's not valid.
            return false
        }

        return self.impl.key.isValidSignature(baseSignature, for: digest)
    }
}
#endif // (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
