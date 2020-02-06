//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
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

@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, macCatalyst 13.0, *)
struct HKDF<H: HashFunction> {
    /// Computes an HKDF using the parameterized Hash Function.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: Input key material.
    ///   - salt: A non-secret random value.
    ///   - info: Context and application specific information.
    ///   - outputByteCount: The desired number of output bytes.
    /// - Returns: Returns the derived key.
    static func deriveKey<IKM: DataProtocol, Salt: DataProtocol, Info: DataProtocol>(inputKeyMaterial: IKM, salt: Salt, info: Info, outputByteCount: Int) -> SymmetricKey {
        return expand(PRK: extract(salt: salt, ikm: inputKeyMaterial), info: info, L: outputByteCount)
    }

    static func extract<S: DataProtocol, IKM: DataProtocol>(salt: S, ikm: IKM) -> HashedAuthenticationCode<H> {
        let key: SymmetricKey
        if salt.regions.count != 1 {
            let contiguousBytes = Array(salt)
            key = SymmetricKey(data: contiguousBytes)
        } else {
            key = SymmetricKey(data: salt.regions.first!)
        }
        
        return HMAC<H>.authenticationCode(for: ikm, using: key)
    }

    static func expand<Info: DataProtocol>(PRK: HashedAuthenticationCode<H>, info: Info?, L: Int) -> SymmetricKey {
        let iterations = UInt8(ceil((Float(L) / Float(H.Digest.byteCount))))
        var output = SecureBytes()
        let key = SymmetricKey(data: Data(PRK.digest))
        var TMinusOne = Data()
        for i in 1...iterations {
            var hmac = HMAC<H>(key: key)
            hmac.update(data: TMinusOne)
            if let infoData = info {
                hmac.update(data: infoData)
            }
            withUnsafeBytes(of: i) { counter in
                hmac.update(bufferPointer: counter)
            }
            TMinusOne = Data(hmac.finalize())
            output.append(TMinusOne)
        }

        let expanded = SymmetricKey(data: output.prefix(L))
        return expanded
    }
}
#endif // Linux or !SwiftPM
