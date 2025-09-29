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

@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims
import Crypto

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
        // This should be SecureBytes, but we can't use that here.
        var derivedKeyData = Data(count: outputByteCount)

        // This computes the maximum amount of memory that will be used by the scrypt algorithm with an additional memory page to spare. This value will be used by the BoringSSL as the memory limit for the algorithm.
        // An additional memory page is added to the computed value (using POSIX specification) to ensure that the memory limit is not too tight.
        let maxMemory = maxMemory ?? (128 * rounds * blockSize * parallelism + getPageSize())

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
                        maxMemory,
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
