##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftCrypto open source project
##
## Copyright (c) 2025 Apple Inc. and the SwiftCrypto project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

add_library(_CryptoExtras
  "Exports.swift")

target_compile_options(_CryptoExtras PRIVATE -DCRYPTO_IN_SWIFTPM)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  target_compile_options(_CryptoExtras PRIVATE -DCRYPTO_IN_SWIFTPM_FORCE_BUILD_API)
endif()

target_link_libraries(_CryptoExtras PUBLIC
  $<$<NOT:$<PLATFORM_ID:Darwin>>:Foundation>
  CryptoExtras)

target_compile_options(_CryptoExtras PRIVATE ${SWIFT_CRYPTO_COMPILE_OPTIONS})

set_target_properties(_CryptoExtras PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_Swift_MODULE_DIRECTORY})

set_property(GLOBAL APPEND PROPERTY SWIFT_CRYPTO_EXPORTS _CryptoExtras)
