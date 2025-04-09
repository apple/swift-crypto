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
#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
@_exported import CryptoKit
#else
@_implementationOnly import CCryptoBoringSSL
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
enum BoringSSLAESWRAPImpl {
    static func wrap(key: SymmetricKey, keyToWrap: SymmetricKey) throws -> Data {
        // There's a flat 8-byte overhead to AES KeyWrap.
        var output = Data(repeating: 0, count: keyToWrap.byteCount + 8)

        let rc = try key.withUnsafeAESKEY(mode: .encrypting) { aesKey in
            output.withUnsafeMutableBytes { outputPtr -> CInt in
                // Memory bind is safe: we cannot alias the pointer here.
                let outputPtr = outputPtr.bindMemory(to: UInt8.self)
                return keyToWrap.withUnsafeBytes { keyToWrapPtr -> CInt in
                    // Memory bind is safe: we cannot alias the pointer here.
                    let keyToWrapPtr = keyToWrapPtr.bindMemory(to: UInt8.self)
                    return CCryptoBoringSSL_AES_wrap_key(
                        aesKey,
                        nil,
                        outputPtr.baseAddress,
                        keyToWrapPtr.baseAddress,
                        keyToWrapPtr.count
                    )
                }
            }
        }

        guard rc >= 0 else {
            throw CryptoKitError.internalBoringSSLError()
        }

        // Assert our 8-byte overhead story was true.
        assert(rc == keyToWrap.byteCount + 8)
        return output.prefix(Int(rc))
    }

    static func unwrap<WrappedKey: DataProtocol>(
        key: SymmetricKey,
        wrappedKey: WrappedKey
    ) throws
        -> SymmetricKey
    {
        if wrappedKey.regions.count == 1 {
            return try self.unwrap(key: key, contiguousWrappedKey: wrappedKey.regions.first!)
        } else {
            let contiguous = Data(wrappedKey)
            return try self.unwrap(key: key, contiguousWrappedKey: contiguous)
        }
    }

    private static func unwrap<WrappedKey: ContiguousBytes>(
        key: SymmetricKey,
        contiguousWrappedKey: WrappedKey
    ) throws -> SymmetricKey {
        let unwrapped = try contiguousWrappedKey.withUnsafeBytes { inPtr in
            try [UInt8](unsafeUninitializedCapacity: inPtr.count) { outputPtr, count in
                // Bind is safe: we cannot violate the aliasing rules here as we never call to arbitrary code.
                let inPtr = inPtr.bindMemory(to: UInt8.self)
                let rc = try key.withUnsafeAESKEY(mode: .decrypting) { aesKey in
                    CCryptoBoringSSL_AES_unwrap_key(
                        aesKey,
                        nil,
                        outputPtr.baseAddress,
                        inPtr.baseAddress,
                        inPtr.count
                    )
                }

                guard rc > 0 else {
                    throw CryptoKitError.internalBoringSSLError()
                }

                // Assert our 8-byte overhead story is true.
                assert(rc == inPtr.count - 8)
                count = Int(rc)
            }
        }

        return SymmetricKey(data: unwrapped)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SymmetricKey {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    fileprivate enum AESKeyMode {
        case encrypting
        case decrypting
    }

    fileprivate func withUnsafeAESKEY<ResultType>(
        mode: AESKeyMode,
        _ body: (UnsafePointer<AES_KEY>) throws -> ResultType
    ) throws -> ResultType {
        try self.withUnsafeBytes { bytesPointer in
            // Bind is safe: cannot alias the pointer here.
            let bytesPointer = bytesPointer.bindMemory(to: UInt8.self)

            var aesKey = AES_KEY()
            let bitsInKey = UInt32(bytesPointer.count * 8)
            let rc: CInt

            switch mode {
            case .encrypting:
                rc = CCryptoBoringSSL_AES_set_encrypt_key(
                    bytesPointer.baseAddress!,
                    bitsInKey,
                    &aesKey
                )
            case .decrypting:
                rc = CCryptoBoringSSL_AES_set_decrypt_key(
                    bytesPointer.baseAddress!,
                    bitsInKey,
                    &aesKey
                )
            }

            guard rc == 0 else {
                throw CryptoKitError.internalBoringSSLError()
            }

            return try withUnsafePointer(to: aesKey) {
                try body($0)
            }
        }
    }
}

#endif  // CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
