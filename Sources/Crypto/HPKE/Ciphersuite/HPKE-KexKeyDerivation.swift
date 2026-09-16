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
import FoundationEssentials
#else
import Foundation
#endif


private let suiteIDLabel = Data("KEM".utf8)

extension HPKE {
    struct KexUtils {
        static func ExtractAndExpand(dh: ContiguousBytes, enc: Data,
                                     pkRm: Data, pkSm: Data? = nil, kem: HPKE.KEM, kdf: HPKE.KDF) -> SymmetricKey {
            var suiteID = suiteIDLabel
            suiteID.append(kem.identifier)
            return Crypto.ExtractAndExpand(zz: dh, kemContext: kemContext(enc: enc, pkRm: pkRm, pkSm: pkSm),
                                                     suiteID: suiteID, kem: kem, kdf: kdf)
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

#endif // canImport(CryptoKit)
