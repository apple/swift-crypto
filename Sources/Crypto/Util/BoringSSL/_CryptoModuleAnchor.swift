//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2024-2026 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// On Apple platforms the Crypto module re-exports CryptoKit and produces no
// symbols of its own. When Xcode 26+ builds SPM packages as dynamic
// frameworks (e.g. for test-target dependencies), an empty module generates a
// framework directory with no Mach-O binary, causing a linker error.
//
// This symbol ensures at least one exported entry is always present in the
// binary, regardless of how the package is linked.
// See: https://github.com/apple/swift-crypto/issues/435

@usableFromInline
internal func _cryptoModuleAnchor() {}
