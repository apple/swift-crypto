##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftCrypto open source project
##
## Copyright (c) 2023 Apple Inc. and the SwiftCrypto project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

add_library(CryptoExtras
  "ChaCha20CTR/BoringSSL/ChaCha20CTR_boring.swift"
  "ChaCha20CTR/ChaCha20CTR.swift"
  "RSA/RSA+BlindSigning.swift"
  "RSA/RSA.swift"
  "RSA/RSA_boring.swift"
  "RSA/RSA_security.swift"
  "Util/BoringSSLHelpers.swift"
  "Util/CryptoKitErrors_boring.swift"
  "Util/DigestType.swift"
  "Util/Error.swift"
  "Util/PEMDocument.swift"
  "Util/RandomBytes.swift"
  "Util/SubjectPublicKeyInfo.swift")

target_include_directories(CryptoExtras PRIVATE
  $<TARGET_PROPERTY:CCryptoBoringSSL,INCLUDE_DIRECTORIES>
  $<TARGET_PROPERTY:CCryptoBoringSSLShims,INCLUDE_DIRECTORIES>)

target_link_libraries(CryptoExtras PUBLIC
  $<$<NOT:$<PLATFORM_ID:Darwin>>:Foundation>
  Crypto
  CryptoBoringWrapper
  CCryptoBoringSSL
  CCryptoBoringSSLShims)

target_compile_options(CryptoExtras PRIVATE ${SWIFT_CRYPTO_COMPILE_OPTIONS})

target_link_options(CryptoExtras PRIVATE
    "$<$<PLATFORM_ID:Darwin>:SHELL:-Xlinker -framework -Xlinker Security>")

set_target_properties(CryptoExtras PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_Swift_MODULE_DIRECTORY})

set_property(GLOBAL APPEND PROPERTY SWIFT_CRYPTO_EXPORTS CryptoExtras)
