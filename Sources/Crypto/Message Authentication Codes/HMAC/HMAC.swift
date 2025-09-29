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
public import FoundationEssentials
#else
public import Foundation
#endif
#endif

/// A hash-based message authentication algorithm.
///
/// Use hash-based message authentication to create a code with a value that’s
/// dependent on both a block of data and a symmetric cryptographic key. Another
/// party with access to the data and the same secret key can compute the code
/// again and compare it to the original to detect whether the data changed.
/// This serves a purpose similar to digital signing and verification, but
/// depends on a shared symmetric key instead of public-key cryptography.
///
/// As with digital signing, the data isn’t hidden by this process. When you
/// need to encrypt the data as well as authenticate it, use a cipher like
/// ``AES`` or ``ChaChaPoly`` to put the data into a sealed box (an instance of
/// ``AES/GCM/SealedBox`` or ``ChaChaPoly/SealedBox``).
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct HMAC<H: HashFunction>: MACAlgorithm, Sendable {
    /// An alias for the symmetric key type used to compute or verify a message
    /// authentication code.
    public typealias Key = SymmetricKey
    /// An alias for a hash-based message authentication code.
    public typealias MAC = HashedAuthenticationCode<H>
    var outerHasher: H
    var innerHasher: H
    
    /// Returns a Boolean value indicating whether the given message
    /// authentication code is valid for a block of data stored in a buffer.
    ///
    /// - Parameters:
    ///   - mac: The authentication code to compare.
    ///   - bufferPointer: A pointer to the block of data to compare.
    ///   - key: The symmetric key for the authentication code.
    ///
    /// - Returns: A Boolean value that’s `true` if the message authentication
    /// code is valid for the data within the specified buffer.
    public static func isValidAuthenticationCode(_ mac: MAC, authenticating bufferPointer: UnsafeRawBufferPointer, using key: SymmetricKey) -> Bool {
        return isValidAuthenticationCode(authenticationCodeBytes: mac, authenticatedData: bufferPointer, key: key)
    }
    
    /// Creates a message authentication code generator.
    ///
    /// - Parameters:
    ///   - key: The symmetric key used to secure the computation.
    public init(key: SymmetricKey) {
        #if os(iOS) && (arch(arm) || arch(i386))
        fatalError("Unsupported architecture")
        #else
        var K: SymmetricKey
        if key.byteCount == H.blockByteCount {
            K = key
        } else if key.byteCount > H.blockByteCount {
            var array = Array(repeating: UInt8(0), count: H.blockByteCount)
            
            K = key.withUnsafeBytes { (keyBytes)  in
                let hash = H.hash(bufferPointer: keyBytes)
                
                return SymmetricKey(data: hash.withUnsafeBytes({ (hashBytes) in
                    memcpy(&array, hashBytes.baseAddress!, hashBytes.count)
                    return array
                }))
            }
        } else {
            var keyArray = Array(repeating: UInt8(0), count: H.blockByteCount)
            key.withUnsafeBytes { keyArray.replaceSubrange(0..<$0.count, with: $0) }
            K = SymmetricKey(data: keyArray)
        }
        
        self.innerHasher = H()
        let innerKey = K.withUnsafeBytes {
            return $0.map({ (keyByte) in
                keyByte ^ 0x36
            })
        }
        innerHasher.update(data: innerKey)
        
        self.outerHasher = H()
        let outerKey = K.withUnsafeBytes {
            return $0.map({ (keyByte) in
                keyByte ^ 0x5c
            })
        }
        outerHasher.update(data: outerKey)
        #endif
    }
    
    /// Computes a message authentication code for the given data.
    ///
    /// - Parameters:
    ///   - data: The data for which to compute the authentication code.
    ///   - key: The symmetric key used to secure the computation.
    ///
    /// - Returns: The message authentication code.
    public static func authenticationCode<D: DataProtocol>(for data: D, using key: SymmetricKey) -> MAC {
        var authenticator = Self(key: key)
        authenticator.update(data: data)
        return authenticator.finalize()
    }
    
    /// Returns a Boolean value indicating whether the given message
    /// authentication code is valid for a block of data.
    ///
    /// - Parameters:
    ///   - authenticationCode: The authentication code to compare.
    ///   - authenticatedData: The block of data to compare.
    ///   - key: The symmetric key for the authentication code.
    ///
    /// - Returns: A Boolean value that’s `true` if the message authentication
    /// code is valid for the specified block of data.
    public static func isValidAuthenticationCode<D: DataProtocol>(_ authenticationCode: MAC, authenticating authenticatedData: D, using key: SymmetricKey) -> Bool {
        return isValidAuthenticationCode(authenticationCodeBytes: authenticationCode, authenticatedData: authenticatedData, key: key)
    }
    
    /// Returns a Boolean value indicating whether the given message
    /// authentication code represented as contiguous bytes is valid for a block
    /// of data.
    ///
    /// - Parameters:
    ///   - authenticationCode: The authentication code to compare.
    ///   - authenticatedData: The block of data to compare.
    ///   - key: The symmetric key for the authentication code.
    ///
    /// - Returns: A Boolean value that’s `true` if the message authentication
    /// code is valid for the specified block of data.
    public static func isValidAuthenticationCode<C: ContiguousBytes, D: DataProtocol>(_ authenticationCode: C,
                                                                                      authenticating authenticatedData: D,
                                                                                      using key: SymmetricKey) -> Bool {
        return isValidAuthenticationCode(authenticationCodeBytes: authenticationCode, authenticatedData: authenticatedData, key: key)
    }
    
    /// Updates the message authentication code computation with a block of
    /// data.
    ///
    /// - Parameters:
    ///   - data: The data for which to compute the authentication code.
    public mutating func update<D: DataProtocol>(data: D) {
        data.regions.forEach { (memoryRegion) in
            memoryRegion.withUnsafeBytes({ (bp) in
                self.update(bufferPointer: bp)
            })
        }
    }
    
    /// Finalizes the message authentication computation and returns the
    /// computed code.
    ///
    /// - Returns: The message authentication code.
    public func finalize() -> MAC {
        let innerHash = innerHasher.finalize()
        var outerHashForFinalization = outerHasher
        
        let mac = innerHash.withUnsafeBytes { buffer -> H.Digest in
            outerHashForFinalization.update(bufferPointer: (buffer))
            return outerHashForFinalization.finalize()
        }
        
        return HashedAuthenticationCode(digest: mac)
    }
    
    /// Adds data to be authenticated by MAC function. This can be called one or more times to append additional data.
    ///
    /// - Parameters:
    ///   - data: The data to be authenticated.
    /// - Throws: Throws if the HMAC has already been finalized.
    mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        innerHasher.update(bufferPointer: bufferPointer)
    }

    /// A common implementation of isValidAuthenticationCode shared by the various entry points.
    private static func isValidAuthenticationCode<C: ContiguousBytes, D: DataProtocol>(authenticationCodeBytes: C,
                                                                                       authenticatedData: D,
                                                                                       key: SymmetricKey) -> Bool {
        var authenticator = Self(key: key)
        authenticator.update(data: authenticatedData)
        let computedMac = authenticator.finalize()
        return safeCompare(authenticationCodeBytes, computedMac)
    }
}

/// A hash-based message authentication code.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct HashedAuthenticationCode<H: HashFunction>: MessageAuthenticationCode, Sendable {
    let digest: H.Digest
    
    /// The number of bytes in the message authentication code.
    public var byteCount: Int {
        return H.Digest.byteCount
    }
    
#if !hasFeature(Embedded)
    /// A human-readable description of the code.
    public var description: String {
        return "HMAC with \(H.self): \(Array(digest).hexString)"
    }
#endif

    /// Invokes the given closure with a buffer pointer covering the raw bytes
    /// of the code.
    ///
    /// - Parameters:
    ///   - body: A closure that takes a raw buffer pointer to the bytes of the
    /// code and returns the code.
    ///
    /// - Returns: The code, as returned from the body closure.
    #if hasFeature(Embedded)
    public func withUnsafeBytes<R, E: Error>(_ body: (UnsafeRawBufferPointer) throws(E) -> R) throws(E) -> R {
        return try digest.withUnsafeBytes(body)
    }
    #else
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try digest.withUnsafeBytes(body)
    }
    #endif
}
#endif // Linux or !SwiftPM
