# This source file is part of the SwiftCrypto open source project
#
# Copyright (c) 2021 Apple Inc. and the SwiftCrypto project authors
# Licensed under Apache License v2.0
#
# See LICENSE.txt for license information
# See CONTRIBUTORS.md for the list of SwiftCrypto project authors
#
# SPDX-License-Identifier: Apache-2.0

add_library(CCryptoBoringSSLShims STATIC shims.c)

target_include_directories(CCryptoBoringSSLShims PUBLIC
  include)

target_link_libraries(CCryptoBoringSSLShims PUBLIC
  CCryptoBoringSSL)

set_property(GLOBAL APPEND PROPERTY SWIFT_CRYPTO_EXPORTS CCryptoBoringSSLShims)
