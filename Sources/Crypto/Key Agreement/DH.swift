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
import Foundation

/// A Diffie-Hellman Key Agreement Key
protocol DiffieHellmanKeyAgreement {
    /// The public key share type to perform the DH Key Agreement
    associatedtype P
    var publicKey: P { get }

    /// Performs a Diffie-Hellman Key Agreement
    ///
    /// - Parameter publicKeyShare: The public key share
    /// - Returns: The resulting key agreement result
    func sharedSecretFromKeyAgreement(with publicKeyShare: P) throws -> SharedSecret
}

/// A Key Agreement Result
/// A SharedSecret has to go through a Key Derivation Function before being able to use by a symmetric key operation.
public struct SharedSecret: ContiguousBytes {
    var ss: SecureBytes

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try ss.withUnsafeBytes(body)
    }

    /// Derives a symmetric encryption key using X9.63 key derivation.
    ///
    /// - Parameters:
    ///   - hashFunction: The Hash Function to use for key derivation.
    ///   - sharedInfo: The Shared Info to use for key derivation.
    ///   - outputByteCount: The length in bytes of resulting symmetric key.
    /// - Returns: The derived symmetric key
    public func x963DerivedSymmetricKey<H: HashFunction, SI: DataProtocol>(using hashFunction: H.Type, sharedInfo: SI, outputByteCount: Int) -> SymmetricKey {
        // SEC1 defines 3 inputs to the KDF:
        //
        // 1. An octet string Z which is the shared secret value. That's `self` here.
        // 2. An integer `keydatalen` which is the length in octets of the keying data to be generated. Here that's `outputByteCount`.
        // 3. An optional octet string `SharedInfo` which consists of other shared data. Here, that's `sharedInfo`.
        //
        // We then need to perform the following steps:
        //
        // 1. Check that keydatalen < hashlen × (2³² − 1). If keydatalen ≥ hashlen × (2³² − 1), fail.
        // 2. Initiate a 4 octet, big-endian octet string Counter as 0x00000001.
        // 3. For i = 1 to ⌈keydatalen/hashlen⌉, do the following:
        //     1. Compute: Ki = Hash(Z || Counter || [SharedInfo]).
        //     2. Increment Counter.
        //     3. Increment i.
        // 4. Set K to be the leftmost keydatalen octets of: K1 || K2 || . . . || K⌈keydatalen/hashlen⌉.
        // 5. Output K.
        //
        // The loop in step 3 is not very Swifty, so instead we generate the counter directly.
        // Step 1: Check that keydatalen < hashlen × (2³² − 1).
        // We do this math in UInt64-space, because we'll overflow 32-bit integers.
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
            hasher.update(self)
            hasher.update(counter.bigEndian)
            hasher.update(data: sharedInfo)
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

    /// Derives a symmetric encryption key using HKDF key derivation.
    ///
    /// - Parameters:
    ///   - hashFunction: The Hash Function to use for key derivation.
    ///   - salt: The salt to use for key derivation.
    ///   - sharedInfo: The Shared Info to use for key derivation.
    ///   - outputByteCount: The length in bytes of resulting symmetric key.
    /// - Returns: The derived symmetric key
    public func hkdfDerivedSymmetricKey<H: HashFunction, Salt: DataProtocol, SI: DataProtocol>(using hashFunction: H.Type, salt: Salt, sharedInfo: SI, outputByteCount: Int) -> SymmetricKey {
        return HKDF<H>.deriveKey(inputKeyMaterial: SymmetricKey(data: ss), salt: salt, info: sharedInfo, outputByteCount: outputByteCount)
    }
}

extension SharedSecret: Hashable {
    public func hash(into hasher: inout Hasher) {
        ss.withUnsafeBytes { hasher.combine(bytes: $0) }
    }
}

// We want to implement constant-time comparison for digests.
extension SharedSecret: CustomStringConvertible, Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        return safeCompare(lhs, rhs)
    }
    
    public static func == <D: DataProtocol>(lhs: Self, rhs: D) -> Bool {
        if rhs.regions.count != 1 {
            let rhsContiguous = Data(rhs)
            return safeCompare(lhs, rhsContiguous)
        } else {
            return safeCompare(lhs, rhs.regions.first!)
        }
    }

    public var description: String {
        return "\(Self.self): \(ss.hexString)"
    }
}

extension HashFunction {
    // A wrapper function to keep the unsafe code in one place.
    mutating func update(_ secret: SharedSecret) {
        secret.withUnsafeBytes {
            self.update(bufferPointer: $0)
        }
    }
    mutating func update(_ counter: UInt32) {
        withUnsafeBytes(of: counter) {
            self.update(bufferPointer: $0)
        }
    }
}

#endif // Linux or !SwiftPM
