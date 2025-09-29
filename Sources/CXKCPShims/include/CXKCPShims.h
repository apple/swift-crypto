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
#ifndef C_XKCP_SHIMS_H
#define C_XKCP_SHIMS_H

// This is for instances when `swift package generate-xcodeproj` is used as CXKCP
// is treated as a framework and requires the framework's name as a prefix.
#if __has_include(<CXKCP/CXKCP.h>)
#include <CXKCP/CXKCP.h>
#else
#include <CXKCP.h>
#endif

#if defined(__cplusplus)
extern "C" {
#endif

// MARK:- Macro wrapper shims
// This section of the code handles shims that wrap XKCP macros as C functions.
// This is done because Swift cannot call C macros directly, so we need to wrap
// them in actual C functions to make them callable from Swift.
//
// The XKCP library defines initialization macros for different SHA-3 variants:
// - Keccak_HashInitialize_SHA3_256  
// - Keccak_HashInitialize_SHA3_384
// - Keccak_HashInitialize_SHA3_512
//
// These macros call Keccak_HashInitialize with specific parameters for each variant.

/**
 * Wrapper function for Keccak_HashInitialize_SHA3_256 macro.
 * Initializes a SHA3-256 hash instance.
 * @param hashInstance Pointer to the hash instance to be initialized.
 * @return KECCAK_SUCCESS if successful, KECCAK_FAIL otherwise.
 */
HashReturn CXKCPShims_Keccak_HashInitialize_SHA3_256(Keccak_HashInstance *hashInstance);

/**
 * Wrapper function for Keccak_HashInitialize_SHA3_384 macro.
 * Initializes a SHA3-384 hash instance.
 * @param hashInstance Pointer to the hash instance to be initialized.
 * @return KECCAK_SUCCESS if successful, KECCAK_FAIL otherwise.
 */
HashReturn CXKCPShims_Keccak_HashInitialize_SHA3_384(Keccak_HashInstance *hashInstance);

/**
 * Wrapper function for Keccak_HashInitialize_SHA3_512 macro.
 * Initializes a SHA3-512 hash instance.
 * @param hashInstance Pointer to the hash instance to be initialized.
 * @return KECCAK_SUCCESS if successful, KECCAK_FAIL otherwise.
 */
HashReturn CXKCPShims_Keccak_HashInitialize_SHA3_512(Keccak_HashInstance *hashInstance);

#if defined(__cplusplus)
}
#endif // defined(__cplusplus)

#endif  // C_XKCP_SHIMS_H
