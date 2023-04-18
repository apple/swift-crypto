##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftCrypto open source project
##
## Copyright (c) 2021 Apple Inc. and the SwiftCrypto project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.md for the list of SwiftCrypto project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

add_library(Crypto
  "AEADs/AES/GCM/AES-GCM.swift"
  "AEADs/AES/GCM/BoringSSL/AES-GCM_boring.swift"
  "AEADs/ChachaPoly/BoringSSL/ChaChaPoly_boring.swift"
  "AEADs/ChachaPoly/ChaChaPoly.swift"
  "AEADs/Cipher.swift"
  "AEADs/Nonces.swift"
  "ASN1/ASN1.swift"
  "ASN1/Basic ASN1 Types/ASN1Any.swift"
  "ASN1/Basic ASN1 Types/ASN1BitString.swift"
  "ASN1/Basic ASN1 Types/ASN1Boolean.swift"
  "ASN1/Basic ASN1 Types/ASN1Identifier.swift"
  "ASN1/Basic ASN1 Types/ASN1Integer.swift"
  "ASN1/Basic ASN1 Types/ASN1Null.swift"
  "ASN1/Basic ASN1 Types/ASN1OctetString.swift"
  "ASN1/Basic ASN1 Types/ASN1Strings.swift"
  "ASN1/Basic ASN1 Types/ArraySliceBigint.swift"
  "ASN1/Basic ASN1 Types/GeneralizedTime.swift"
  "ASN1/Basic ASN1 Types/ObjectIdentifier.swift"
  "ASN1/ECDSASignature.swift"
  "ASN1/PEMDocument.swift"
  "ASN1/PKCS8PrivateKey.swift"
  "ASN1/SEC1PrivateKey.swift"
  "ASN1/SubjectPublicKeyInfo.swift"
  "CryptoKitErrors.swift"
  "Digests/BoringSSL/Digest_boring.swift"
  "Digests/Digest.swift"
  "Digests/Digests.swift"
  "Digests/HashFunctions.swift"
  "Digests/HashFunctions_SHA2.swift"
  "Insecure/Insecure.swift"
  "Insecure/Insecure_HashFunctions.swift"
  "Key Agreement/BoringSSL/ECDH_boring.swift"
  "Key Agreement/DH.swift"
  "Key Agreement/ECDH.swift"
  "Key Derivation/HKDF.swift"
  "Key Wrapping/AESWrap.swift"
  "Key Wrapping/BoringSSL/AESWrap_boring.swift"
  "Keys/EC/BoringSSL/Ed25519_boring.swift"
  "Keys/EC/BoringSSL/EllipticCurvePoint_boring.swift"
  "Keys/EC/BoringSSL/EllipticCurve_boring.swift"
  "Keys/EC/BoringSSL/NISTCurvesKeys_boring.swift"
  "Keys/EC/BoringSSL/X25519Keys_boring.swift"
  "Keys/EC/Curve25519.swift"
  "Keys/EC/Ed25519.swift"
  "Keys/EC/NISTCurvesKeys.swift"
  "Keys/EC/X25519Keys.swift"
  "Keys/Symmetric/SymmetricKeys.swift"
  "Message Authentication Codes/HMAC/HMAC.swift"
  "Message Authentication Codes/MACFunctions.swift"
  "Message Authentication Codes/MessageAuthenticationCode.swift"
  "PRF/AES.swift"
  "Signatures/BoringSSL/ECDSASignature_boring.swift"
  "Signatures/BoringSSL/ECDSA_boring.swift"
  "Signatures/BoringSSL/EdDSA_boring.swift"
  "Signatures/ECDSA.swift"
  "Signatures/EdDSA.swift"
  "Signatures/Signature.swift"
  "Util/BoringSSL/ArbitraryPrecisionInteger_boring.swift"
  "Util/BoringSSL/CryptoKitErrors_boring.swift"
  "Util/BoringSSL/FiniteFieldArithmeticContext_boring.swift"
  "Util/BoringSSL/RNG_boring.swift"
  "Util/BoringSSL/SafeCompare_boring.swift"
  "Util/BoringSSL/Zeroization_boring.swift"
  "Util/PrettyBytes.swift"
  "Util/SafeCompare.swift"
  "Util/SecureBytes.swift"
  "Util/Zeroization.swift")

target_compile_definitions(Crypto PRIVATE
  "$<$<COMPILE_LANGUAGE:Swift>:CRYPTO_IN_SWIFTPM>")
target_include_directories(Crypto PRIVATE
  $<TARGET_PROPERTY:CCryptoBoringSSL,INCLUDE_DIRECTORIES>
  $<TARGET_PROPERTY:CCryptoBoringSSLShims,INCLUDE_DIRECTORIES>
  $<TARGET_PROPERTY:CryptoBoringWrapper,INCLUDE_DIRECTORIES>)
target_link_libraries(Crypto PUBLIC
  $<$<NOT:$<PLATFORM_ID:Darwin>>:dispatch>
  $<$<NOT:$<PLATFORM_ID:Darwin>>:Foundation>
  CCryptoBoringSSL
  CCryptoBoringSSLShims
  CryptoBoringWrapper)
set_target_properties(Crypto PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_Swift_MODULE_DIRECTORY})

_install_target(Crypto)
set_property(GLOBAL APPEND PROPERTY SWIFT_CRYPTO_EXPORTS Crypto)
