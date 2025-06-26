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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension HPKE {

    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    internal enum Mode: CaseIterable {
        case base
        case psk
        case auth
        case auth_psk
        
        var value: UInt8 {
            switch self {
            case .base:     return 0x00
            case .psk:      return 0x01
            case .auth:     return 0x02
            case .auth_psk: return 0x03
            }
        }
        
        static var pskModes: [HPKE.Mode] {
            return [Mode.psk, Mode.auth_psk]
        }
    }
}

#endif // Linux or !SwiftPM
