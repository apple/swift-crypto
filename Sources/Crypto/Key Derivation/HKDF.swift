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

#if canImport(CryptoKit)
@_exported import CryptoKit
#else

#if canImport(FoundationEssentials)
public import FoundationEssentials
#else
public import Foundation
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
public struct HKDF<H: HashFunction>: Sendable {
    /// Derives a symmetric encryption key from a main key or passcode using
    /// HKDF key derivation with information and salt you specify.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: The main key or passcode the derivation function
    /// uses to derive a key.
    ///   - salt: The salt to use for key derivation.
    ///   - info: The shared information to use for key derivation.
    ///   - outputKey: An output span that will be populated with the derived
    ///   symmetric key.
    #if swift(<6.3)
    @_lifetime(outputKey: copy outputKey)
    #endif
    public static func deriveKey(inputKeyMaterial: SymmetricKey,
                                 salt: RawSpan? = nil,
                                 info: RawSpan? = nil,
                                 output outputKey: inout OutputRawSpan) {
        let code = extract(inputKeyMaterial: inputKeyMaterial, salt: salt)
        code.withUnsafeBytes { codeBytes in
            expand(
                pseudoRandomKey: codeBytes.bytes,
                info: info,
                into: &outputKey
            )
        }
    }

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
    public static func deriveKey<Salt: DataProtocol, Info: DataProtocol>(
        inputKeyMaterial: SymmetricKey,
        salt: Salt,
        info: Info,
        outputByteCount: Int
    ) -> SymmetricKey {
        // Fast path: Both salt and info have a single contiguous region, so
        // go directly to the span.
        if salt.regions.count == 1 && info.regions.count == 1 {
            return salt.regions.first!.withUnsafeBytes { saltBytes in
                info.regions.first!.withUnsafeBytes { infoBytes in
                    SymmetricKey(size: SymmetricKeySize(bitCount: outputByteCount * 8)) { output in
                        deriveKey(
                            inputKeyMaterial: inputKeyMaterial,
                            salt: saltBytes.bytes,
                            info: infoBytes.bytes,
                            output: &output
                        )
                    }
                }
            }
        }

        // Turn salt and info into contiguous regions, then recurse.
        let contiguousSalt = Array(salt)
        let contiguousInfo = Array(info)
        return deriveKey(
            inputKeyMaterial: inputKeyMaterial,
            salt: contiguousSalt,
            info: contiguousInfo,
            outputByteCount: outputByteCount
        )
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
        
        return HMAC<H>.authenticationCode(for: inputKeyMaterial.bytes, using: key)
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
    public static func extract(inputKeyMaterial: SymmetricKey, salt: RawSpan?) -> HashedAuthenticationCode<H> {
        let key = if let salt {
            SymmetricKey(bytes: salt)
        } else {
            SymmetricKey(data: SecureBytes())
        }
        
        return HMAC<H>.authenticationCode(for: inputKeyMaterial.bytes, using: key)
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
        SymmetricKey(capacity: outputByteCount) { output in
            prk.withUnsafeBytes { prkBuffer in
                guard let info else {
                    self.expand(pseudoRandomKey: prkBuffer.bytes, info: nil, into: &output)
                    return
                }
                
                if info.regions.count == 1 {
                    info.regions.first!.withUnsafeBytes { infoBuffer in
                        self.expand(pseudoRandomKey: prkBuffer.bytes, info: infoBuffer.bytes, into: &output)
                    }
                } else {
                    let contiguous = ContiguousArray(info)
                    self.expand(pseudoRandomKey: prkBuffer.bytes, info: contiguous.span.bytes, into: &output)
                }
            }
            
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
    #if swift(<6.3)
    @_lifetime(output: copy output)
    #endif
    public static func expand(pseudoRandomKey prk: RawSpan, info: RawSpan?, into output: inout OutputRawSpan) {
        let iterations: UInt8 = UInt8((Double(output.freeCapacity) / Double(H.Digest.byteCount)).rounded(.up))

        let key = SymmetricKey(bytes: prk)
        var lastIterationBytes = 0
        for i in 1...iterations {
            var hmac = HMAC<H>(key: key)
            hmac.update(bytes: output.bytes.extracting(last: lastIterationBytes))
            if let info {
                hmac.update(bytes: info)
            }

            var buf = i
            withUnsafeBytes(of: &buf) { rawBuffer in
                let span = RawSpan(_unsafeBytes: rawBuffer)
                hmac.update(bytes: span)
            }
            hmac.finalize().withUnsafeBytes {
                let bytesToAppend = $0.bytes.extracting(first: output.freeCapacity)
                output.append(contentsOf: bytesToAppend)
                lastIterationBytes = bytesToAppend.byteCount
            }
        }
    }
}
#endif // canImport(CryptoKit)
