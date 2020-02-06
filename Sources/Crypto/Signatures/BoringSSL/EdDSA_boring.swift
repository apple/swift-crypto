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
@_implementationOnly import CCryptoBoringSSLShims
import Foundation

extension Curve25519.Signing.PublicKey {
    // We do this to enable inlinability on these methods.
    @usableFromInline
    static let signatureLength = Curve25519.Signing.signatureLength

    @inlinable
    func openSSLIsValidSignature<S: DataProtocol, D: DataProtocol>(_ signature: S, for data: D) -> Bool {
        if signature.count != Curve25519.Signing.PublicKey.signatureLength {
            return false
        }

        // Both fields are potentially discontiguous, so we need to check and flatten them.
        switch (signature.regions.count, data.regions.count) {
        case (1, 1):
            // Both data protocols are secretly contiguous.
            return self.openSSLIsValidSignature(contiguousSignature: signature.regions.first!, contiguousData: data.regions.first!)
        case (1, _):
            // The data isn't contiguous: we make it so.
            return self.openSSLIsValidSignature(contiguousSignature: signature.regions.first!, contiguousData: Array(data))
        case (_, 1):
            // The signature isn't contiguous, make it so.
            return self.openSSLIsValidSignature(contiguousSignature: Array(signature), contiguousData: data.regions.first!)
        case (_, _):
            // Neither are contiguous.
            return self.openSSLIsValidSignature(contiguousSignature: Array(signature), contiguousData: Array(data))
        }
    }

    @inlinable
    func openSSLIsValidSignature<S: ContiguousBytes, D: ContiguousBytes>(contiguousSignature signature: S, contiguousData data: D) -> Bool {
        return signature.withUnsafeBytes { signaturePointer in
            data.withUnsafeBytes { dataPointer in
                self.openSSLIsValidSignature(signaturePointer: signaturePointer, dataPointer: dataPointer)
            }
        }
    }

    // We need this factored out because self.keyBytes is not @usableFromInline, and so we can't see it.
    @usableFromInline
    func openSSLIsValidSignature(signaturePointer: UnsafeRawBufferPointer, dataPointer: UnsafeRawBufferPointer) -> Bool {
        precondition(signaturePointer.count == Curve25519.Signing.PublicKey.signatureLength)
        precondition(self.keyBytes.count == 32)
        let rc: CInt = self.keyBytes.withUnsafeBytes { keyBytesPtr in
            CCryptoBoringSSLShims_ED25519_verify(dataPointer.baseAddress,
                                                 dataPointer.count,
                                                 signaturePointer.baseAddress,
                                                 keyBytesPtr.baseAddress)
        }

        return rc == 1
    }
}

extension Curve25519.Signing.PrivateKey {
    @inlinable
    func openSSLSignature<D: DataProtocol>(for data: D) throws -> Data {
        if data.regions.count == 1 {
            return try self.openSSLSignature(forContiguousData: data.regions.first!)
        } else {
            return try self.openSSLSignature(forContiguousData: Array(data))
        }
    }

    @inlinable
    func openSSLSignature<C: ContiguousBytes>(forContiguousData data: C) throws -> Data {
        return try data.withUnsafeBytes {
            try self.openSSLSignature(forDataPointer: $0)
        }
    }

    @usableFromInline
    func openSSLSignature(forDataPointer dataPointer: UnsafeRawBufferPointer) throws -> Data {
        var signature = Data(repeating: 0, count: Curve25519.Signing.PublicKey.signatureLength)

        let rc: CInt = signature.withUnsafeMutableBytes { signaturePointer in
            self.key.withUnsafeBytes { keyPointer in
                precondition(signaturePointer.count == Curve25519.Signing.PublicKey.signatureLength)
                precondition(keyPointer.count == ED25519_PRIVATE_KEY_LEN)

                return CCryptoBoringSSLShims_ED25519_sign(signaturePointer.baseAddress, dataPointer.baseAddress, dataPointer.count, keyPointer.baseAddress)
            }
        }

        if rc != 1 {
            throw CryptoKitError.internalBoringSSLError()
        }

        return signature
    }
}
#endif // (os(macOS) || os(iOS) || os(watchOS) || os(tvOS)) && CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
