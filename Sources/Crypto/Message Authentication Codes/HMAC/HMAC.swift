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

/// Performs HMAC - Keyed-Hashing for Message Authentication
/// Reference: https://tools.ietf.org/html/rfc2104
public struct HMAC<H: HashFunction>: MACAlgorithm {
    public typealias Key = SymmetricKey
    public typealias MAC = HashedAuthenticationCode<H>
    var outerHasher: H
    var innerHasher: H
    
    /// Verifies a tag of a Message Authentication Code. The comparison is done in constant-time.
    ///
    /// - Parameters:
    ///   - key: The key used to authenticate the data
    ///   - data: The data to authenticate
    ///   - mac: The MAC to verify
    /// - Returns: Returns true if the MAC is valid. False otherwise.
    public static func isValidAuthenticationCode(_ mac: MAC, authenticating bufferPointer: UnsafeRawBufferPointer, using key: SymmetricKey) -> Bool {
        return isValidAuthenticationCode(authenticationCodeBytes: mac, authenticatedData: bufferPointer, key: key)
    }
    
    /// Initializes an incremental HMAC
    ///
    /// - Parameter key: The key to use for HMAC.
    public init(key: SymmetricKey) {
        var K: ContiguousBytes
        
        if key.byteCount == H.blockByteCount {
            K = key
        } else if key.byteCount > H.blockByteCount {
            var array = Array(repeating: UInt8(0), count: H.blockByteCount)
            
            K = key.withUnsafeBytes { (keyBytes)  in
                let hash = H.hash(bufferPointer: keyBytes)
                
                return hash.withUnsafeBytes({ (hashBytes) in
                    memcpy(&array, hashBytes.baseAddress!, hashBytes.count)
                    return array
                })
            }
        } else {
            var keyArray = Array(repeating: UInt8(0), count: H.blockByteCount)
            key.withUnsafeBytes { keyArray.replaceSubrange(0..<$0.count, with: $0) }
            K = keyArray
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
    }
    
    /// Computes a Message Authentication Code.
    ///
    /// - Parameters:
    ///   - key: The key used to authenticate the data
    ///   - data: The data to authenticate
    /// - Returns: A Message Authentication Code
    public static func authenticationCode<D: DataProtocol>(for data: D, using key: SymmetricKey) -> MAC {
        var authenticator = Self(key: key)
        authenticator.update(data: data)
        return authenticator.finalize()
    }
    
    /// Verifies a Message Authentication Code. The comparison is done in constant-time.
    ///
    /// - Parameters:
    ///   - authenticationCode: The authentication code
    ///   - authenticatedData: Authenticated Data
    ///   - key: The key to authenticate the data with
    /// - Returns: Returns true if the MAC is valid. False otherwise.
    public static func isValidAuthenticationCode<D: DataProtocol>(_ authenticationCode: MAC, authenticating authenticatedData: D, using key: SymmetricKey) -> Bool {
        return isValidAuthenticationCode(authenticationCodeBytes: authenticationCode, authenticatedData: authenticatedData, key: key)
    }
    
    /// Verifies a Message Authentication Code. The comparison is done in constant-time.
    ///
    /// - Parameters:
    ///   - authenticationCode: The authentication code
    ///   - authenticatedData: Authenticated Data
    ///   - key: The key to authenticate the data with
    /// - Returns: Returns true if the MAC is valid. False otherwise.
    public static func isValidAuthenticationCode<C: ContiguousBytes, D: DataProtocol>(_ authenticationCode: C,
                                                                                      authenticating authenticatedData: D,
                                                                                      using key: SymmetricKey) -> Bool {
        return isValidAuthenticationCode(authenticationCodeBytes: authenticationCode, authenticatedData: authenticatedData, key: key)
    }
    
    /// Updates the MAC with data.
    ///
    /// - Parameter data: The data to update the MAC
    public mutating func update<D: DataProtocol>(data: D) {
        data.regions.forEach { (memoryRegion) in
            memoryRegion.withUnsafeBytes({ (bp) in
                self.update(bufferPointer: bp)
            })
        }
    }
    
    /// Returns the Message Authentication Code (MAC) from the data inputted into the MAC.
    ///
    /// - Returns: The Message Authentication Code
    /// - Throws: Throws if the MAC has already been finalized
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
    /// - Parameter data: The data to be authenticated
    /// - Throws: Throws if the HMAC has already been finalized
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

/// A structure that contains a Message Authentication Code that was computed from a Hash Function using HMAC.
public struct HashedAuthenticationCode<H: HashFunction>: MessageAuthenticationCode {
    let digest: H.Digest
    
    public var byteCount: Int {
        return H.Digest.byteCount
    }
    
    public var description: String {
        return "HMAC with \(H.self): \(Array(digest).hexString)"
    }
    
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try digest.withUnsafeBytes(body)
    }
}
#endif // Linux or !SwiftPM
