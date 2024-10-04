/* Copyright (c) 2024, Google LLC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <CCryptoBoringSSL_slhdsa.h>

#include <string.h>

#include <CCryptoBoringSSL_rand.h>

#include "../internal.h"
#include "address.h"
#include "fors.h"
#include "internal.h"
#include "merkle.h"
#include "params.h"
#include "thash.h"


void SLHDSA_SHA2_128S_generate_key_from_seed(
    uint8_t out_public_key[SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES],
    uint8_t out_secret_key[SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES],
    const uint8_t seed[3 * SLHDSA_SHA2_128S_N]) {
  // Initialize SK.seed || SK.prf || PK.seed from seed.
  OPENSSL_memcpy(out_secret_key, seed, 3 * SLHDSA_SHA2_128S_N);

  // Initialize PK.seed from seed.
  OPENSSL_memcpy(out_public_key, seed + 2 * SLHDSA_SHA2_128S_N,
                 SLHDSA_SHA2_128S_N);

  uint8_t addr[32] = {0};
  slhdsa_set_layer_addr(addr, SLHDSA_SHA2_128S_D - 1);

  // Set PK.root
  slhdsa_treehash(out_public_key + SLHDSA_SHA2_128S_N, out_secret_key, 0,
                  SLHDSA_SHA2_128S_TREE_HEIGHT, out_public_key, addr);
  OPENSSL_memcpy(out_secret_key + 3 * SLHDSA_SHA2_128S_N,
                 out_public_key + SLHDSA_SHA2_128S_N, SLHDSA_SHA2_128S_N);
}

void SLHDSA_SHA2_128S_generate_key(
    uint8_t out_public_key[SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES],
    uint8_t out_private_key[SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES]) {
  uint8_t seed[3 * SLHDSA_SHA2_128S_N];
  RAND_bytes(seed, 3 * SLHDSA_SHA2_128S_N);
  SLHDSA_SHA2_128S_generate_key_from_seed(out_public_key, out_private_key,
                                          seed);
}

OPENSSL_EXPORT void SLHDSA_SHA2_128S_public_from_private(
    uint8_t out_public_key[SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES],
    const uint8_t private_key[SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES]) {
  OPENSSL_memcpy(out_public_key, private_key + 2 * SLHDSA_SHA2_128S_N,
                 SLHDSA_SHA2_128S_N * 2);
}

// Note that this overreads by a byte. This is fine in the context that it's
// used.
static uint64_t load_tree_index(const uint8_t in[8]) {
  static_assert(SLHDSA_SHA2_128S_TREE_BYTES == 7,
                "This code needs to be updated");
  uint64_t index = CRYPTO_load_u64_be(in);
  index >>= 8;
  index &= (~(uint64_t)0) >> (64 - SLHDSA_SHA2_128S_TREE_BITS);
  return index;
}

// Implements Algorithm 22: slh_sign function (Section 10.2.1, page 39)
void SLHDSA_SHA2_128S_sign_internal(
    uint8_t out_signature[SLHDSA_SHA2_128S_SIGNATURE_BYTES],
    const uint8_t secret_key[SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES],
    const uint8_t header[SLHDSA_M_PRIME_HEADER_LEN], const uint8_t *context,
    size_t context_len, const uint8_t *msg, size_t msg_len,
    const uint8_t entropy[SLHDSA_SHA2_128S_N]) {
  const uint8_t *sk_seed = secret_key;
  const uint8_t *sk_prf = secret_key + SLHDSA_SHA2_128S_N;
  const uint8_t *pk_seed = secret_key + 2 * SLHDSA_SHA2_128S_N;
  const uint8_t *pk_root = secret_key + 3 * SLHDSA_SHA2_128S_N;

  // Derive randomizer R and copy it to signature
  uint8_t R[SLHDSA_SHA2_128S_N];
  slhdsa_thash_prfmsg(R, sk_prf, entropy, header, context, context_len, msg,
                      msg_len);
  OPENSSL_memcpy(out_signature, R, SLHDSA_SHA2_128S_N);

  // Compute message digest
  uint8_t digest[SLHDSA_SHA2_128S_DIGEST_SIZE];
  slhdsa_thash_hmsg(digest, R, pk_seed, pk_root, header, context, context_len,
                    msg, msg_len);

  uint8_t fors_digest[SLHDSA_SHA2_128S_FORS_MSG_BYTES];
  OPENSSL_memcpy(fors_digest, digest, SLHDSA_SHA2_128S_FORS_MSG_BYTES);

  const uint64_t idx_tree =
      load_tree_index(digest + SLHDSA_SHA2_128S_FORS_MSG_BYTES);
  uint32_t idx_leaf = CRYPTO_load_u16_be(
      digest + SLHDSA_SHA2_128S_FORS_MSG_BYTES + SLHDSA_SHA2_128S_TREE_BYTES);
  idx_leaf &= (~(uint32_t)0) >> (32 - SLHDSA_SHA2_128S_LEAF_BITS);

  uint8_t addr[32] = {0};
  slhdsa_set_tree_addr(addr, idx_tree);
  slhdsa_set_type(addr, SLHDSA_SHA2_128S_ADDR_TYPE_FORSTREE);
  slhdsa_set_keypair_addr(addr, idx_leaf);

  slhdsa_fors_sign(out_signature + SLHDSA_SHA2_128S_N, fors_digest, sk_seed,
                   pk_seed, addr);

  uint8_t pk_fors[SLHDSA_SHA2_128S_N];
  slhdsa_fors_pk_from_sig(pk_fors, out_signature + SLHDSA_SHA2_128S_N,
                          fors_digest, pk_seed, addr);

  slhdsa_ht_sign(
      out_signature + SLHDSA_SHA2_128S_N + SLHDSA_SHA2_128S_FORS_BYTES, pk_fors,
      idx_tree, idx_leaf, sk_seed, pk_seed);
}

int SLHDSA_SHA2_128S_sign(
    uint8_t out_signature[SLHDSA_SHA2_128S_SIGNATURE_BYTES],
    const uint8_t private_key[SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES],
    const uint8_t *msg, size_t msg_len, const uint8_t *context,
    size_t context_len) {
  if (context_len > 255) {
    return 0;
  }

  // Construct header for M' as specified in Algorithm 22
  uint8_t M_prime_header[2];
  M_prime_header[0] = 0;  // domain separator for pure signing
  M_prime_header[1] = (uint8_t)context_len;

  uint8_t entropy[SLHDSA_SHA2_128S_N];
  RAND_bytes(entropy, sizeof(entropy));
  SLHDSA_SHA2_128S_sign_internal(out_signature, private_key, M_prime_header,
                                 context, context_len, msg, msg_len, entropy);
  return 1;
}

// Implements Algorithm 24: slh_verify function (Section 10.3, page 41)
int SLHDSA_SHA2_128S_verify(
    const uint8_t *signature, size_t signature_len,
    const uint8_t public_key[SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES],
    const uint8_t *msg, size_t msg_len, const uint8_t *context,
    size_t context_len) {
  if (context_len > 255) {
    return 0;
  }

  // Construct header for M' as specified in Algorithm 24
  uint8_t M_prime_header[2];
  M_prime_header[0] = 0;  // domain separator for pure verification
  M_prime_header[1] = (uint8_t)context_len;

  return SLHDSA_SHA2_128S_verify_internal(signature, signature_len, public_key,
                                          M_prime_header, context, context_len,
                                          msg, msg_len);
}

int SLHDSA_SHA2_128S_verify_internal(
    const uint8_t *signature, size_t signature_len,
    const uint8_t public_key[SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES],
    const uint8_t header[SLHDSA_M_PRIME_HEADER_LEN], const uint8_t *context,
    size_t context_len, const uint8_t *msg, size_t msg_len) {
  if (signature_len != SLHDSA_SHA2_128S_SIGNATURE_BYTES) {
    return 0;
  }
  const uint8_t *pk_seed = public_key;
  const uint8_t *pk_root = public_key + SLHDSA_SHA2_128S_N;

  const uint8_t *r = signature;
  const uint8_t *sig_fors = signature + SLHDSA_SHA2_128S_N;
  const uint8_t *sig_ht = sig_fors + SLHDSA_SHA2_128S_FORS_BYTES;

  uint8_t digest[SLHDSA_SHA2_128S_DIGEST_SIZE];
  slhdsa_thash_hmsg(digest, r, pk_seed, pk_root, header, context, context_len,
                    msg, msg_len);

  uint8_t fors_digest[SLHDSA_SHA2_128S_FORS_MSG_BYTES];
  OPENSSL_memcpy(fors_digest, digest, SLHDSA_SHA2_128S_FORS_MSG_BYTES);

  const uint64_t idx_tree =
      load_tree_index(digest + SLHDSA_SHA2_128S_FORS_MSG_BYTES);
  uint32_t idx_leaf = CRYPTO_load_u16_be(
      digest + SLHDSA_SHA2_128S_FORS_MSG_BYTES + SLHDSA_SHA2_128S_TREE_BYTES);
  idx_leaf &= (~(uint32_t)0) >> (32 - SLHDSA_SHA2_128S_LEAF_BITS);

  uint8_t addr[32] = {0};
  slhdsa_set_tree_addr(addr, idx_tree);
  slhdsa_set_type(addr, SLHDSA_SHA2_128S_ADDR_TYPE_FORSTREE);
  slhdsa_set_keypair_addr(addr, idx_leaf);

  uint8_t pk_fors[SLHDSA_SHA2_128S_N];
  slhdsa_fors_pk_from_sig(pk_fors, sig_fors, fors_digest, pk_seed, addr);

  return slhdsa_ht_verify(sig_ht, pk_fors, idx_tree, idx_leaf, pk_root,
                          pk_seed);
}
