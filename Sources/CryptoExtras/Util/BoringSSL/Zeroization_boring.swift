//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#if !canImport(Darwin)
@_implementationOnly import CCryptoBoringSSL

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
typealias errno_t = CInt

// This is a Swift wrapper for the libc function that does not exist on Linux. We shim it via a call to OPENSSL_cleanse.
// We have the same syntax, but mostly ignore it.
@discardableResult
func memset_s(_ s: UnsafeMutableRawPointer!, _ smax: Int, _ byte: CInt, _ n: Int) -> errno_t {
    assert(smax == n, "memset_s invariant not met")
    assert(byte == 0, "memset_s used to not zero anything")
    CCryptoBoringSSL_OPENSSL_cleanse(s, smax)
    return 0
}
#endif
