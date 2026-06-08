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

#if !CRYPTOKIT_STATIC_LIBRARY
@available(iOS 17.0, macOS 10.15, watchOS 10.0, tvOS 17.0, macCatalyst 17.0, *)
#else // CRYPTOKIT_STATIC_LIBRARY
@available(iOS 16.0, macOS 10.13, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 1.0, *)
#endif
extension HPKE {
    #if !CRYPTOKIT_STATIC_LIBRARY
    @available(iOS 17.0, macOS 10.15, watchOS 10.0, tvOS 17.0, macCatalyst 17.0, *)
    #else // CRYPTOKIT_STATIC_LIBRARY
    @available(iOS 16.0, macOS 10.13, watchOS 9.0, tvOS 16.0, macCatalyst 16.0, visionOS 1.0, *)
    #endif

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
