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
import SwiftSystem
#else
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
#endif


private let suiteIDLabel = Data("KEM".utf8)

#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 17.0, macOS 10.15, watchOS 10.0, tvOS 17.0, macCatalyst 17.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 16.0, macOS 10.13, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 1.0, *)
#endif
extension HPKE {
    struct KexUtils {
        static func ExtractAndExpand(dh: ContiguousBytes, enc: Data,
                                     pkRm: Data, pkSm: Data? = nil, kem: HPKE.KEM, kdf: HPKE.KDF) -> SymmetricKey {
            var suiteID = suiteIDLabel
            suiteID.append(kem.identifier)
            #if  !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API
            #if CRYPTOKIT_STATIC_LIBRARY
            return CryptoKit_Static.ExtractAndExpand(zz: dh, kemContext: kemContext(enc: enc, pkRm: pkRm, pkSm: pkSm),
                                                     suiteID: suiteID, kem: kem, kdf: kdf)
            #else
            return CryptoKit.ExtractAndExpand(zz: dh, kemContext: kemContext(enc: enc, pkRm: pkRm, pkSm: pkSm),
                                                     suiteID: suiteID, kem: kem, kdf: kdf)
            #endif
            #else
            return Crypto.ExtractAndExpand(zz: dh, kemContext: kemContext(enc: enc, pkRm: pkRm, pkSm: pkSm),
                                                     suiteID: suiteID, kem: kem, kdf: kdf)
            #endif
        }
        
        static func kemContext(enc: Data, pkRm: Data, pkSm: Data? = nil) -> Data {
            var context = Data()
            context.append(enc)
            context.append(pkRm)
            if let pkSm { context.append(pkSm) }
            return context
        }
    }
}

#endif // Linux or !SwiftPM
