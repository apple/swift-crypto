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

/// A standards-based implementation of an HMAC-based Key Derivation Function
/// (HKDF).
///
/// The key derivation functions allow you to derive one or more secrets of the
/// size of your choice from a main key or passcode. The key derivation function
/// is compliant with IETF RFC 5869. Use one of the `deriveKey` functions, such
/// as ``deriveKey(inputKeyMaterial:outputByteCount:)`` or
/// ``deriveKey(inputKeyMaterial:salt:info:outputByteCount:)``, to derive a key
/// from a main secret or passcode in a single function.
///
/// To derive a key with more fine-grained control, use
/// ``extract(inputKeyMaterial:salt:)`` to create cryptographically strong key
/// material in the form of a hashed authentication code, then call
/// ``expand(pseudoRandomKey:info:outputByteCount:)`` using that key material to
/// generate a symmetric key of the length you specify.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct HKDF<H: HashFunction>: Sendable {
    /// Derives a symmetric encryption key from a main key or passcode using
    /// HKDF key derivation with information and salt you specify.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: The main key or passcode the derivation function
    /// uses to derive a key.
    ///   - salt: The salt to use for key derivation.
    ///   - info: The shared information to use for key derivation.
    ///   - outputByteCount: The length in bytes of the resulting symmetric key.
    ///
    /// - Returns: The derived symmetric key.
    public static func deriveKey<Salt: DataProtocol, Info: DataProtocol>(inputKeyMaterial: SymmetricKey,
                                                                         salt: Salt,
                                                                         info: Info,
                                                                         outputByteCount: Int) -> SymmetricKey {
        return expand(pseudoRandomKey: extract(inputKeyMaterial: inputKeyMaterial, salt: salt), info: info, outputByteCount: outputByteCount)
    }
    
    /// Derives a symmetric encryption key from a main key or passcode using
    /// HKDF key derivation with information you specify.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: The main key or passcode the derivation function
    /// uses to derive a key.
    ///   - info: The shared information to use for key derivation.
    ///   - outputByteCount: The length in bytes of the resulting symmetric key.
    ///
    /// - Returns: The derived symmetric key.
    public static func deriveKey<Info: DataProtocol>(inputKeyMaterial: SymmetricKey,
                                                     info: Info,
                                                     outputByteCount: Int) -> SymmetricKey {
        return deriveKey(inputKeyMaterial: inputKeyMaterial, salt: [UInt8](), info: info, outputByteCount: outputByteCount)
    }
    
    /// Derives a symmetric encryption key from a main key or passcode using
    /// HKDF key derivation with salt that you specify.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: The main key or passcode the derivation function
    /// uses to derive a key.
    ///   - salt: The salt to use for key derivation.
    ///   - outputByteCount: The length in bytes of the resulting symmetric key.
    ///
    /// - Returns: The derived symmetric key.
    public static func deriveKey<Salt: DataProtocol>(inputKeyMaterial: SymmetricKey,
                                                     salt: Salt,
                                                     outputByteCount: Int) -> SymmetricKey {
        return deriveKey(inputKeyMaterial: inputKeyMaterial, salt: salt, info: [UInt8](), outputByteCount: outputByteCount)
    }
    
    /// Derives a symmetric encryption key from a main key or passcode using
    /// HKDF key derivation.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: The main key or passcode the derivation function
    /// uses to derive a key.
    ///   - outputByteCount: The length in bytes of the resulting symmetric key.
    ///
    /// - Returns: The derived symmetric key.
    public static func deriveKey(inputKeyMaterial: SymmetricKey,
                                 outputByteCount: Int) -> SymmetricKey {
        return deriveKey(inputKeyMaterial: inputKeyMaterial, salt: [UInt8](), info: [UInt8](), outputByteCount: outputByteCount)
    }
    
    /// Creates cryptographically strong key material from a main key or
    /// passcode that you specify.
    ///
    /// Generate a derived symmetric key from the cryptographically strong key
    /// material this function creates by calling
    /// ``expand(pseudoRandomKey:info:outputByteCount:)``.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: The main key or passcode the derivation function
    /// uses to derive a key.
    ///   - salt: The salt to use for key derivation.
    ///
    /// - Returns: A pseudorandom, cryptographically strong key in the form of a
    /// hashed authentication code.
    public static func extract<Salt: DataProtocol>(inputKeyMaterial: SymmetricKey, salt: Salt?) -> HashedAuthenticationCode<H> {
        let key: SymmetricKey
        if let salt {
            if salt.regions.count != 1 {
                let contiguousBytes = Array(salt)
                key = SymmetricKey(data: contiguousBytes)
            } else {
                key = SymmetricKey(data: salt.regions.first!)
            }
        } else {
            key = SymmetricKey(data: [UInt8]())
        }
        
        return inputKeyMaterial.withUnsafeBytes { ikmBytes in
            return HMAC<H>.authenticationCode(for: ikmBytes, using: key)
        }
    }
    
    /// Expands cryptographically strong key material into a derived symmetric
    /// key.
    ///
    /// Generate cryptographically strong key material to use with this function
    /// by calling ``extract(inputKeyMaterial:salt:)``.
    ///
    /// - Parameters:
    ///   - prk: A pseudorandom, cryptographically strong key generated from the
    /// ``extract(inputKeyMaterial:salt:)`` function.
    ///   - info: The shared information to use for key derivation.
    ///   - outputByteCount: The length in bytes of the resulting symmetric key.
    ///
    /// - Returns: The derived symmetric key.
    public static func expand<PRK: ContiguousBytes, Info: DataProtocol>(pseudoRandomKey prk: PRK, info: Info?, outputByteCount: Int) -> SymmetricKey {
       
        let iterations: UInt8 = UInt8((Double(outputByteCount) / Double(H.Digest.byteCount)).rounded(.up))

        var output = SecureBytes()
        let key = SymmetricKey(data: prk)
        var TMinusOne = SecureBytes()
        for i in 1...iterations {
            var hmac = HMAC<H>(key: key)
            hmac.update(data: TMinusOne)
            if let info {
                hmac.update(data: info)
            }
            
            withUnsafeBytes(of: i) { counter in
                hmac.update(bufferPointer: counter)
            }
            TMinusOne = SecureBytes(bytes: hmac.finalize())
            output.append(TMinusOne)
        }
        
        return SymmetricKey(data: output.prefix(outputByteCount))
    }
}
#endif // Linux or !SwiftPM
