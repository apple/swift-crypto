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

#if CRYPTOKIT_NO_ACCESS_TO_FOUNDATION
public import SwiftSystem
#else
#if canImport(FoundationEssentials)
public import FoundationEssentials
#else
public import Foundation
#endif
#endif

@_spi(ANSIKDF)
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct ANSIKDFx963<H: HashFunction>: Sendable {
    public static func deriveKey<Info: DataProtocol>(inputKeyMaterial: SymmetricKey, info: Info, outputByteCount: Int) -> SymmetricKey {
        
        guard UInt64(outputByteCount) < (UInt64(H.Digest.byteCount) * UInt64(UInt32.max)) else {
            fatalError("Invalid parameter size")
        }
        
        var key = SecureBytes()
        key.reserveCapacity(outputByteCount)
        
        var remainingBytes = outputByteCount
        var counter = UInt32(1)
        
        while remainingBytes > 0 {
            // 1. Compute: Ki = Hash(Z || Counter || [SharedInfo]).
            var hasher = H()
            inputKeyMaterial.withUnsafeBytes { ikmBytes in
                hasher.update(data: ikmBytes)
            }
            hasher.update(counter.bigEndian)
            hasher.update(data: info)
            let digest = hasher.finalize()
            
            // 2. Increment Counter.
            counter += 1
            
            // Append the bytes of the digest. We don't want to append more than the remaining number of bytes.
            let bytesToAppend = min(remainingBytes, H.Digest.byteCount)
            digest.withUnsafeBytes { digestPtr in
                key.append(digestPtr.prefix(bytesToAppend))
            }
            remainingBytes -= bytesToAppend
        }
        
        precondition(key.count == outputByteCount)
        return SymmetricKey(data: key)
    }
    
    public static func deriveKey(inputKeyMaterial: SymmetricKey,
                                 outputByteCount: Int) -> SymmetricKey {
        return deriveKey(inputKeyMaterial: inputKeyMaterial, info: [UInt8](), outputByteCount: outputByteCount)
    }
}


#endif

