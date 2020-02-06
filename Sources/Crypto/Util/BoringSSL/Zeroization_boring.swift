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
#if !(os(macOS) || os(iOS) || os(watchOS) || os(tvOS))
@_implementationOnly import CCryptoBoringSSL

// This is a Swift wrapper for the libc function that does not exist on Linux. We shim it via a call to OPENSSL_cleanse.
// We have the same syntax, but mostly ignore it.
func memset_s(_ s: UnsafeMutableRawPointer!, _ smax: Int, _ byte: CInt, _ n: Int) {
    assert(smax == n, "memset_s invariant not met")
    assert(byte == 0, "memset_s used to not zero anything")
    CCryptoBoringSSL_OPENSSL_cleanse(s, smax)
}
#endif
