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
  "CryptoError_boring.swift"
  "CryptoKitErrors.swift"
  "Digests/BoringSSL/Digest_boring.swift"
  "Digests/Digest.swift"
  "Digests/Digests.swift"
  "Digests/HashFunctions.swift"
  "Digests/HashFunctions_SHA2.swift"
  "Digests/HashFunctions_SHA3.swift"
  "Digests/XKCP/Digest_xkcp.swift"
  "HPKE/Ciphersuite/HPKE-AEAD.swift"
  "HPKE/Ciphersuite/HPKE-Ciphersuite.swift"
  "HPKE/Ciphersuite/HPKE-KDF.swift"
  "HPKE/Ciphersuite/HPKE-KexKeyDerivation.swift"
  "HPKE/Ciphersuite/HPKE-LabeledExtract.swift"
  "HPKE/Ciphersuite/HPKE-Utils.swift"
  "HPKE/Ciphersuite/KEM/Conformances/DHKEM.swift"
  "HPKE/Ciphersuite/KEM/Conformances/HPKE-KEM-Curve25519.swift"
  "HPKE/Ciphersuite/KEM/Conformances/HPKE-NIST-EC-KEMs.swift"
  "HPKE/Ciphersuite/KEM/HPKE-KEM.swift"
  "HPKE/HPKE-Errors.swift"
  "HPKE/HPKE.swift"
  "HPKE/Key Schedule/HPKE-Context.swift"
  "HPKE/Key Schedule/HPKE-KeySchedule.swift"
  "HPKE/Modes/HPKE-Modes.swift"
  "Insecure/Insecure.swift"
  "Insecure/Insecure_HashFunctions.swift"
  "KEM/BoringSSL/MLKEM_boring.swift"
  "KEM/BoringSSL/MLKEM_wrapper.swift"
  "KEM/BoringSSL/XWing_boring.swift"
  "KEM/KEM-Errors.swift"
  "KEM/KEM.swift"
  "KEM/MLKEM.swift"
  "KEM/XWing.swift"
  "Key Agreement/BoringSSL/ECDH_boring.swift"
  "Key Agreement/DH.swift"
  "Key Agreement/ECDH.swift"
  "Key Derivation/ANSIx963.swift"
  "Key Derivation/HKDF.swift"
  "Key Wrapping/AESWrap.swift"
  "Key Wrapping/BoringSSL/AESWrap_boring.swift"
  "Keys/EC/BoringSSL/Ed25519_boring.swift"
  "Keys/EC/BoringSSL/NISTCurvesKeys_boring.swift"
  "Keys/EC/BoringSSL/X25519Keys_boring.swift"
  "Keys/EC/Curve25519.swift"
  "Keys/EC/Ed25519Keys.swift"
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
  "Signatures/BoringSSL/MLDSA_boring.swift"
  "Signatures/BoringSSL/MLDSA_wrapper.swift"
  "Signatures/ECDSA.swift"
  "Signatures/Ed25519.swift"
  "Signatures/MLDSA.swift"
  "Signatures/Signature.swift"
  "Util/BoringSSL/CryptoKitErrors_boring.swift"
  "Util/BoringSSL/Optional+withUnsafeBytes_boring.swift"
  "Util/BoringSSL/RNG_boring.swift"
  "Util/BoringSSL/SafeCompare_boring.swift"
  "Util/BoringSSL/Zeroization_boring.swift"
  "Util/PrettyBytes.swift"
  "Util/SafeCompare.swift"
  "Util/SecureBytes.swift"
  "Util/Zeroization.swift"
)

target_compile_definitions(Crypto PRIVATE
  "$<$<COMPILE_LANGUAGE:Swift>:CRYPTO_IN_SWIFTPM>")

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  target_compile_definitions(Crypto PRIVATE
    "$<$<COMPILE_LANGUAGE:Swift>:CRYPTO_IN_SWIFTPM_FORCE_BUILD_API>")
endif()

target_include_directories(Crypto PRIVATE
  $<TARGET_PROPERTY:CCryptoBoringSSL,INCLUDE_DIRECTORIES>
  $<TARGET_PROPERTY:CCryptoBoringSSLShims,INCLUDE_DIRECTORIES>
  $<TARGET_PROPERTY:CryptoBoringWrapper,INCLUDE_DIRECTORIES>
  $<TARGET_PROPERTY:CXKCP,INCLUDE_DIRECTORIES>
  $<TARGET_PROPERTY:CXKCPShims,INCLUDE_DIRECTORIES>)
target_link_libraries(Crypto PUBLIC
  $<$<NOT:$<PLATFORM_ID:Darwin>>:dispatch>
  $<$<NOT:$<PLATFORM_ID:Darwin>>:Foundation>
  CCryptoBoringSSL
  CCryptoBoringSSLShims
  CryptoBoringWrapper
  CXKCP
  CXKCPShims)
target_compile_options(Crypto PRIVATE ${SWIFT_CRYPTO_COMPILE_OPTIONS})
set_target_properties(Crypto PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_Swift_MODULE_DIRECTORY})

_install_target(Crypto)
set_property(GLOBAL APPEND PROPERTY SWIFT_CRYPTO_EXPORTS Crypto)
