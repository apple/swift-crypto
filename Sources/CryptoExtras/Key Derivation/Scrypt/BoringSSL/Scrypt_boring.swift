//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto

#if hasFeature(SourceWarningControl)
@diagnose(ImplementationOnlyDeprecated, as: ignored) @_implementationOnly import CCryptoBoringSSL
#else
@_implementationOnly import CCryptoBoringSSL
#endif

#if canImport(FoundationEssentials)
#if os(Windows)
import ucrt
#elseif canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Android)
import Android
#elseif canImport(WASILibc)
import WASILibc
#endif
import FoundationEssentials
#else
import Foundation
#endif

#if canImport(Android)
import Android
#endif

#if os(Windows)
import WinSDK

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
private func getPageSize() -> Int {
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    var info = SYSTEM_INFO()
    GetSystemInfo(&info)
    return Int(info.dwPageSize)
}
#else
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
private func getPageSize() -> Int {
    Int(sysconf(Int32(_SC_PAGESIZE)))
}
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
internal struct BoringSSLScrypt {
    /// Derives a secure key using the provided passphrase and salt.
    ///
    /// - Parameters:
    ///    - password: The passphrase, which should be used as a basis for the key. This can be any type that conforms to `DataProtocol`, like `Data` or an array of `UInt8` instances.
    ///    - salt: The salt to use for key derivation.
    ///    - outputByteCount: The length in bytes of resulting symmetric key.
    ///    - rounds: The number of rounds which should be used to perform key derivation. Must be a power of 2.
    ///    - blockSize: The block size to be used by the algorithm.
    ///    - parallelism: The parallelism factor indicating how many threads should be run in parallel.
    /// - Returns: The derived symmetric key.
    static func deriveKey<Passphrase: DataProtocol, Salt: DataProtocol>(
        from password: Passphrase,
        salt: Salt,
        outputByteCount: Int,
        rounds: Int,
        blockSize: Int,
        parallelism: Int,
        maxMemory: Int? = nil
    ) throws -> SymmetricKey {
        // SecureBytes is internal to Crypto, so zero the buffer by hand once the key has been copied out.
        var derivedKeyData = Data(count: outputByteCount)
        defer { derivedKeyData.withUnsafeMutableBytes { $0.zeroize() } }

        let memoryLimit: Int
        if let maxMemory {
            memoryLimit = maxMemory
        } else {
            // BoringSSL needs 128 * blockSize * (rounds + parallelism + 1) bytes; one page is added as slack.
            let (blockBytes, blockBytesOverflowed) = 128.multipliedReportingOverflow(by: blockSize)
            let (scratchBlockCount, scratchBlockCountOverflowed) = rounds.addingReportingOverflow(parallelism)
            let (blockCount, blockCountOverflowed) = scratchBlockCount.addingReportingOverflow(1)
            let (stateBytes, stateBytesOverflowed) = blockBytes.multipliedReportingOverflow(by: blockCount)
            let (computedLimit, computedLimitOverflowed) = stateBytes.addingReportingOverflow(getPageSize())
            guard
                !blockBytesOverflowed, !scratchBlockCountOverflowed, !blockCountOverflowed, !stateBytesOverflowed,
                !computedLimitOverflowed
            else {
                throw CryptoKitError.incorrectParameterSize
            }
            memoryLimit = computedLimit
        }

        let result = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes -> Int32 in
            let saltBytes: ContiguousBytes = salt.regions.count == 1 ? salt.regions.first! : Array(salt)
            return saltBytes.withUnsafeBytes { saltBytes -> Int32 in
                let passwordBytes: ContiguousBytes =
                    password.regions.count == 1 ? password.regions.first! : Array(password)
                return passwordBytes.withUnsafeBytes { passwordBytes -> Int32 in
                    CCryptoBoringSSL_EVP_PBE_scrypt(
                        passwordBytes.baseAddress!,
                        passwordBytes.count,
                        saltBytes.baseAddress!,
                        saltBytes.count,
                        UInt64(rounds),
                        UInt64(blockSize),
                        UInt64(parallelism),
                        memoryLimit,
                        derivedKeyBytes.baseAddress!,
                        derivedKeyBytes.count
                    )
                }
            }
        }

        guard result == 1 else {
            throw CryptoKitError.internalBoringSSLError()
        }

        return SymmetricKey(data: derivedKeyData)
    }
}
