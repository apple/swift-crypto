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

cmake_minimum_required(VERSION 3.15.1)

if(POLICY CMP0157)
  cmake_policy(SET CMP0157 NEW)
endif()

project(SwiftCrypto
  LANGUAGES ASM C CXX Swift)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules)

include(SwiftSupport)

if(CMAKE_VERSION VERSION_LESS 3.16 AND CMAKE_SYSTEM_NAME STREQUAL Windows)
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
else()
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
endif()
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_Swift_MODULE_DIRECTORY ${CMAKE_BINARY_DIR}/swift)

set(SWIFT_CRYPTO_COMPILE_OPTIONS
    -package-name com.apple.swift-crypto
)

option(BUILD_SHARED_LIBS "Build shared libraries by default" YES)

if(BUILD_SHARED_LIBS)
  set(CMAKE_POSITION_INDEPENDENT_CODE YES)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL Darwin AND NOT CMAKE_CROSSCOMPILING)
  set(CMAKE_AR "/usr/bin/ar")
  set(CMAKE_C_ARCHIVE_CREATE "<CMAKE_AR> crs <TARGET> <LINK_FLAGS> <OBJECTS>")
  set(CMAKE_RANLIB "/usr/bin/ranlib")
endif()

set(CMAKE_CXX_STANDARD 17)
if(CMAKE_SYSTEM_NAME STREQUAL Windows)
  # We need to ensure that we don't include the min/max macros from the Windows SDK.
  add_compile_definitions(NOMINMAX)
  # We can only link against the DLL version of the MSVC runtime library for now.
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
  if(CMAKE_Swift_COMPILER_VERSION VERSION_EQUAL 0.0.0 OR CMAKE_Swift_COMPILER_VERSION VERSION_GREATER_EQUAL 6.2)
    # We need to set the static library prefix to "lib" so that we can link against the static libraries.
    set(CMAKE_STATIC_LIBRARY_PREFIX_Swift "lib")
  endif()
endif()

if(NOT CMAKE_SYSTEM_NAME STREQUAL Darwin)
  find_package(dispatch CONFIG)
  find_package(Foundation CONFIG)
endif()

include(FetchContent)
find_package(SwiftASN1 CONFIG)
if(NOT SwiftASN1_FOUND)
  message("-- Vending swift-asn1")
  FetchContent_Declare(ASN1
    GIT_REPOSITORY https://github.com/apple/swift-asn1
    GIT_TAG 1.3.1)
  FetchContent_MakeAvailable(ASN1)
endif()

add_subdirectory(Sources)
add_subdirectory(cmake/modules)
