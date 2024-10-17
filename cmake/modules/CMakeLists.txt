##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftCrypto open source project
##
## Copyright (c) 2021 Apple Inc. and the SwiftCrypto project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

set(SWIFT_CRYPTO_EXPORTS_FILE ${CMAKE_CURRENT_BINARY_DIR}/SwiftCryptoExports.cmake)
configure_file(SwiftCryptoConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/SwiftCryptoConfig.cmake)

get_property(SWIFT_CRYPTO_EXPORTS GLOBAL PROPERTY SWIFT_CRYPTO_EXPORTS)
export(TARGETS ${SWIFT_CRYPTO_EXPORTS} FILE ${SWIFT_CRYPTO_EXPORTS_FILE})
