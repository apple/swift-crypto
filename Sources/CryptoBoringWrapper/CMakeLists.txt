##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftCrypto open source project
##
## Copyright (c) 2022 Apple Inc. and the SwiftCrypto project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

add_library(CryptoBoringWrapper STATIC
  "AEAD/BoringSSLAEAD.swift"
  "CryptoKitErrors_boring.swift"
  "EC/EllipticCurve.swift"
  "EC/EllipticCurvePoint.swift"
  "Util/ArbitraryPrecisionInteger.swift"
  "Util/FiniteFieldArithmeticContext.swift"
  "Util/RandomBytes.swift"
)

target_include_directories(CryptoBoringWrapper PUBLIC
  $<TARGET_PROPERTY:CCryptoBoringSSL,INCLUDE_DIRECTORIES>
  $<TARGET_PROPERTY:CCryptoBoringSSLShims,INCLUDE_DIRECTORIES>)

target_link_libraries(CryptoBoringWrapper PUBLIC
  $<$<NOT:$<PLATFORM_ID:Darwin>>:Foundation>
  CCryptoBoringSSL
  CCryptoBoringSSLShims)

target_compile_options(CryptoBoringWrapper PRIVATE ${SWIFT_CRYPTO_COMPILE_OPTIONS})

set_target_properties(CryptoBoringWrapper PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_Swift_MODULE_DIRECTORY})

set_property(GLOBAL APPEND PROPERTY SWIFT_CRYPTO_EXPORTS CryptoBoringWrapper)
