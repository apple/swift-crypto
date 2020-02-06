//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
#include <CCryptoBoringSSLShims.h>

// MARK:- Pointer type shims
// This section of the code handles shims that change uint8_t* pointers to
// void *s. This is done because Swift does not have the rule that C does, that
// pointers to uint8_t can safely alias any other pointer. That means that Swift
// Unsafe[Mutable]RawPointer cannot be passed to uint8_t * APIs, which is very
// awkward, so we shim these to avoid the need to call bindMemory in Swift (which is
// wrong).
//
// Our relevant citation is: https://github.com/apple/swift-nio-extras/pull/56#discussion_r329330295.
// We want this to land: https://bugs.swift.org/browse/SR-11087. Once that lands we can remove these
// shims.
int CCryptoBoringSSLShims_EVP_AEAD_CTX_init(EVP_AEAD_CTX *ctx, const EVP_AEAD *aead,
                                            const void *key, size_t key_len, size_t tag_len,
                                            ENGINE *impl) {
    return CCryptoBoringSSL_EVP_AEAD_CTX_init(ctx, aead, key, key_len, tag_len, impl);
}

int CCryptoBoringSSLShims_EVP_AEAD_CTX_seal_scatter(
    const EVP_AEAD_CTX *ctx,
    void *out,
    void *out_tag,
    size_t *out_tag_len,
    size_t max_out_tag_len,
    const void *nonce,
    size_t nonce_len,
    const void *in,
    size_t in_len,
    const void *extra_in,
    size_t extra_in_len,
    const void *ad,
    size_t ad_len) {
    return CCryptoBoringSSL_EVP_AEAD_CTX_seal_scatter(ctx, out, out_tag, out_tag_len, max_out_tag_len, nonce, nonce_len, in, in_len, extra_in, extra_in_len, ad, ad_len);
}

int CCryptoBoringSSLShims_EVP_AEAD_CTX_open_gather(const EVP_AEAD_CTX *ctx, void *out,
                                                   const void *nonce, size_t nonce_len,
                                                   const void *in, size_t in_len,
                                                   const void *in_tag, size_t in_tag_len,
                                                   const void *ad, size_t ad_len) {
    return CCryptoBoringSSL_EVP_AEAD_CTX_open_gather(ctx, out, nonce, nonce_len, in, in_len, in_tag, in_tag_len, ad, ad_len);
}

void CCryptoBoringSSLShims_ED25519_keypair(void *out_public_key, void *out_private_key) {
    CCryptoBoringSSL_ED25519_keypair(out_public_key, out_private_key);
}

void CCryptoBoringSSLShims_ED25519_keypair_from_seed(void *out_public_key,
                                                     void *out_private_key,
                                                     const void *seed) {
    CCryptoBoringSSL_ED25519_keypair_from_seed(out_public_key, out_private_key, seed);
}

ECDSA_SIG *CCryptoBoringSSLShims_ECDSA_do_sign(const void *digest, size_t digest_len,
                                               const EC_KEY *eckey) {
    return CCryptoBoringSSL_ECDSA_do_sign(digest, digest_len, eckey);
}

int CCryptoBoringSSLShims_ECDSA_do_verify(const void *digest, size_t digest_len,
                                          const ECDSA_SIG *sig, const EC_KEY *eckey) {
    return CCryptoBoringSSL_ECDSA_do_verify(digest, digest_len, sig, eckey);
}

void CCryptoBoringSSLShims_X25519_keypair(void *out_public_value, void *out_private_key) {
    CCryptoBoringSSL_X25519_keypair(out_public_value, out_private_key);
}

void CCryptoBoringSSLShims_X25519_public_from_private(void *out_public_value,
                                                      const void *private_key) {
    CCryptoBoringSSL_X25519_public_from_private(out_public_value, private_key);
}

int CCryptoBoringSSLShims_X25519(void *out_shared_key, const void *private_key,
                                 const void *peer_public_value) {
    return CCryptoBoringSSL_X25519(out_shared_key, private_key, peer_public_value);
}

ECDSA_SIG *CCryptoBoringSSLShims_ECDSA_SIG_from_bytes(const void *in, size_t in_len) {
    return CCryptoBoringSSL_ECDSA_SIG_from_bytes(in, in_len);
}

int CCryptoBoringSSLShims_ED25519_verify(const void *message, size_t message_len,
                                         const void *signature, const void *public_key) {
    return CCryptoBoringSSL_ED25519_verify(message, message_len, signature, public_key);
}

int CCryptoBoringSSLShims_ED25519_sign(void *out_sig, const void *message,
                                       size_t message_len, const void *private_key) {
    return CCryptoBoringSSL_ED25519_sign(out_sig, message, message_len, private_key);
}

BIGNUM *CCryptoBoringSSLShims_BN_bin2bn(const void *in, size_t len, BIGNUM *ret) {
    return CCryptoBoringSSL_BN_bin2bn(in, len, ret);
}

size_t CCryptoBoringSSLShims_BN_bn2bin(const BIGNUM *in, void *out) {
    return CCryptoBoringSSL_BN_bn2bin(in, out);
}
