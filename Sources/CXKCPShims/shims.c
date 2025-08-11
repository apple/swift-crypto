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
#include <CXKCPShims.h>

// MARK:- Macro wrapper shims
// This section of the code handles shims that wrap XKCP macros as C functions.
// This is done because Swift cannot call C macros directly, so we need to wrap
// them in actual C functions to make them callable from Swift.
//
// The XKCP library defines initialization macros for different SHA-3 variants:
// - Keccak_HashInitialize_SHA3_256 -> Keccak_HashInitialize(hashInstance, 1088, 512, 256, 0x06)
// - Keccak_HashInitialize_SHA3_384 -> Keccak_HashInitialize(hashInstance, 832, 768, 384, 0x06)
// - Keccak_HashInitialize_SHA3_512 -> Keccak_HashInitialize(hashInstance, 576, 1024, 512, 0x06)

HashReturn CXKCPShims_Keccak_HashInitialize_SHA3_256(Keccak_HashInstance *hashInstance) {
    return Keccak_HashInitialize(hashInstance, 1088, 512, 256, 0x06);
}

HashReturn CXKCPShims_Keccak_HashInitialize_SHA3_384(Keccak_HashInstance *hashInstance) {
    return Keccak_HashInitialize(hashInstance, 832, 768, 384, 0x06);
}

HashReturn CXKCPShims_Keccak_HashInitialize_SHA3_512(Keccak_HashInstance *hashInstance) {
    return Keccak_HashInitialize(hashInstance, 576, 1024, 512, 0x06);
}
