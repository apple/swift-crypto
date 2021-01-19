# This source file is part of the SwiftCrypto open source project
#
# Copyright (c) 2021 Apple Inc. and the SwiftCrypto project authors
# Licensed under Apache License v2.0
#
# See LICENSE.txt for license information
# See CONTRIBUTORS.md for the list of SwiftCrypto project authors
#
# SPDX-License-Identifier: Apache-2.0

set(CRYPTO_EXPORTS_FILE ${CMAKE_CURRENT_BINARY_DIR}/CryptoExports.cmake)
configure_file(CryptoConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/CryptoConfig.cmake)

get_property(CRYPTO_EXPORTS GLOBAL PROPERTY CRYPTO_EXPORTS)
export(TARGETS ${CRYPTO_EXPORTS} FILE ${CRYPTO_EXPORTS_FILE})
