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

add_library(CXKCPShims STATIC
  "shims.c"
)

target_include_directories(CXKCPShims PUBLIC
  include
  $<TARGET_PROPERTY:CXKCP,INCLUDE_DIRECTORIES>)

target_link_libraries(CXKCPShims PUBLIC
  CXKCP)

set_target_properties(CXKCPShims PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_Swift_MODULE_DIRECTORY})

set_property(GLOBAL APPEND PROPERTY SWIFT_CRYPTO_EXPORTS CXKCPShims)
