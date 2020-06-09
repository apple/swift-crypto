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

/// The HMAC-based Extract-and-Expand Key Derivation Function (IETF RFC 5869)
/// https://tools.ietf.org/html/rfc5869
public struct HKDF<H: HashFunction> {
    /// Derives a symmetric key using the HKDF algorithm.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: Input key material.
    ///   - salt: A non-secret random value.
    ///   - info: Context and application specific information.
    ///   - outputByteCount: The desired number of output bytes.
    /// - Returns: The derived key
    public static func deriveKey<Salt: DataProtocol, Info: DataProtocol>(inputKeyMaterial: SymmetricKey,
                                                                         salt: Salt,
                                                                         info: Info,
                                                                         outputByteCount: Int) -> SymmetricKey {
        return expand(pseudoRandomKey: extract(inputKeyMaterial: inputKeyMaterial, salt: salt), info: info, outputByteCount: outputByteCount)
    }
    
    /// Derives a symmetric key using the HKDF algorithm.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: Input key material.
    ///   - info: Context and application specific information.
    ///   - outputByteCount: The desired number of output bytes.
    /// - Returns: The derived key
    public static func deriveKey<Info: DataProtocol>(inputKeyMaterial: SymmetricKey,
                                                     info: Info,
                                                     outputByteCount: Int) -> SymmetricKey {
        return deriveKey(inputKeyMaterial: inputKeyMaterial, salt: [UInt8](), info: info, outputByteCount: outputByteCount)
    }
    
    /// Derives a symmetric key using the HKDF algorithm.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: Input key material.
    ///   - salt: A non-secret random value.
    ///   - outputByteCount: The desired number of output bytes.
    /// - Returns: The derived key
    public static func deriveKey<Salt: DataProtocol>(inputKeyMaterial: SymmetricKey,
                                                     salt: Salt,
                                                     outputByteCount: Int) -> SymmetricKey {
        return deriveKey(inputKeyMaterial: inputKeyMaterial, salt: salt, info: [UInt8](), outputByteCount: outputByteCount)
    }
    
    /// Derives a symmetric key using the HKDF algorithm.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: Input key material.
    ///   - outputByteCount: The desired number of output bytes.
    /// - Returns: The derived key
    public static func deriveKey(inputKeyMaterial: SymmetricKey,
                                 outputByteCount: Int) -> SymmetricKey {
        return deriveKey(inputKeyMaterial: inputKeyMaterial, salt: [UInt8](), info: [UInt8](), outputByteCount: outputByteCount)
    }
    
    /// The extract function as defined by specification.
    /// The goal of the extract function is to "concentrate" the possibly dispersed entropy of the input keying material into a short, but cryptographically strong, pseudorandom key.
    /// Unless required by a specification, it is recommended to use the one-shot "deriveKey" API instead that performs both extraction and expansion.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: Input key material.
    ///   - salt: A non-secret random value.
    /// - Returns: The resulting secret
    public static func extract<Salt: DataProtocol>(inputKeyMaterial: SymmetricKey, salt: Salt?) -> HashedAuthenticationCode<H> {
        let key: SymmetricKey
        if let salt = salt {
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
    
    /// The expand function as defined by the specification.
    /// The goal of the expand function is to expand the pseudorandom key to the desired length.
    /// Unless required by a specification, it is recommended to use the one-shot "deriveKey" API instead that performs both extraction and expansion.
    ///
    /// - Parameters:
    ///   - pseudoRandomKey: The extracted pseudorandom key. This value is expected to be a high-entropy secret. In the HKDF specification it is obtained from the input key material and the salt using the extract method.
    ///   - info: Context and application specific information.
    ///   - outputByteCount: The desired number of output bytes.
    /// - Returns: The expanded key bytes.
    public static func expand<PRK: ContiguousBytes, Info: DataProtocol>(pseudoRandomKey prk: PRK, info: Info?, outputByteCount: Int) -> SymmetricKey {
        let iterations: UInt8 = UInt8(ceil((Float(outputByteCount) / Float(H.Digest.byteCount))))
        var output = SecureBytes()
        let key = SymmetricKey(data: prk)
        var TMinusOne = Data()
        for i in 1...iterations {
            var hmac = HMAC<H>(key: key)
            hmac.update(data: TMinusOne)
            if let info = info {
                hmac.update(data: info)
            }
            
            withUnsafeBytes(of: i) { counter in
                hmac.update(bufferPointer: counter)
            }
            TMinusOne = Data(hmac.finalize())
            output.append(TMinusOne)
        }
        
        return SymmetricKey(data: output.prefix(outputByteCount))
    }
}
#endif // Linux or !SwiftPM
