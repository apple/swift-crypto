//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_implementationOnly import CCryptoBoringSSL
@_implementationOnly import CCryptoBoringSSLShims
import Crypto
@_implementationOnly import CryptoBoringWrapper
import Foundation

public struct BoringSSLSPXImpl {
    public static func testSPX() -> Bool {
        let publicKey = UnsafeMutablePointer<UInt8>.allocate(capacity: 32)
        let secretKey = UnsafeMutablePointer<UInt8>.allocate(capacity: 64)
        let message = [UInt8]("Hello, World!".utf8)
        let messagePointer = UnsafeMutablePointer<UInt8>.allocate(capacity: message.count)
        messagePointer.initialize(from: message, count: message.count)
        let signature = UnsafeMutablePointer<UInt8>.allocate(capacity: 7856)
        
        CCryptoBoringSSL_spx_generate_key(publicKey, secretKey)
        CCryptoBoringSSL_spx_sign(signature, secretKey, messagePointer, message.count, 0)
        return (CCryptoBoringSSL_spx_verify(signature, publicKey, messagePointer, message.count) == 1)
    }
}
