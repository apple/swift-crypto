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

#ifndef OPENSSL_HEADER_CRYPTO_SLHDSA_PARAMS_H
#define OPENSSL_HEADER_CRYPTO_SLHDSA_PARAMS_H

#include <CCryptoBoringSSL_base.h>

#if defined(__cplusplus)
extern "C" {
#endif


// Output length of the hash function.
#define SLHDSA_SHA2_128S_N 16
// Total height of the tree structure.
#define SLHDSA_SHA2_128S_FULL_HEIGHT 63
// Number of subtree layers.
#define SLHDSA_SHA2_128S_D 7
// Height of the trees on each layer
#define SLHDSA_SHA2_128S_TREE_HEIGHT 9
// Height of each individual FORS tree.
#define SLHDSA_SHA2_128S_FORS_HEIGHT 12
// Total number of FORS tree used.
#define SLHDSA_SHA2_128S_FORS_TREES 14
// Size of a FORS signature
#define SLHDSA_SHA2_128S_FORS_BYTES                                   \
  ((SLHDSA_SHA2_128S_FORS_HEIGHT + 1) * SLHDSA_SHA2_128S_FORS_TREES * \
   SLHDSA_SHA2_128S_N)
// The number of bytes at the beginning of M', the augmented message, before the
// context.
#define SLHDSA_M_PRIME_HEADER_LEN 2

// Winternitz parameter and derived values
#define SLHDSA_SHA2_128S_WOTS_W 16
#define SLHDSA_SHA2_128S_WOTS_LOG_W 4
#define SLHDSA_SHA2_128S_WOTS_LEN1 32
#define SLHDSA_SHA2_128S_WOTS_LEN2 3
#define SLHDSA_SHA2_128S_WOTS_LEN 35
#define SLHDSA_SHA2_128S_WOTS_BYTES \
  (SLHDSA_SHA2_128S_N * SLHDSA_SHA2_128S_WOTS_LEN)

// XMSS sizes
#define SLHDSA_SHA2_128S_XMSS_BYTES \
  (SLHDSA_SHA2_128S_WOTS_BYTES +    \
   (SLHDSA_SHA2_128S_N * SLHDSA_SHA2_128S_TREE_HEIGHT))

// Size of the message digest (NOTE: This is only correct for the SHA-256 params
// here)
#define SLHDSA_SHA2_128S_DIGEST_SIZE                                           \
  (((SLHDSA_SHA2_128S_FORS_TREES * SLHDSA_SHA2_128S_FORS_HEIGHT) / 8) +        \
   (((SLHDSA_SHA2_128S_FULL_HEIGHT - SLHDSA_SHA2_128S_TREE_HEIGHT) / 8) + 1) + \
   (SLHDSA_SHA2_128S_TREE_HEIGHT / 8) + 1)

// Compressed address size when using SHA-256
#define SLHDSA_SHA2_128S_SHA256_ADDR_BYTES 22

// Size of the FORS message hash
#define SLHDSA_SHA2_128S_FORS_MSG_BYTES \
  ((SLHDSA_SHA2_128S_FORS_HEIGHT * SLHDSA_SHA2_128S_FORS_TREES + 7) / 8)
#define SLHDSA_SHA2_128S_TREE_BITS \
  (SLHDSA_SHA2_128S_TREE_HEIGHT * (SLHDSA_SHA2_128S_D - 1))
#define SLHDSA_SHA2_128S_TREE_BYTES ((SLHDSA_SHA2_128S_TREE_BITS + 7) / 8)
#define SLHDSA_SHA2_128S_LEAF_BITS SLHDSA_SHA2_128S_TREE_HEIGHT
#define SLHDSA_SHA2_128S_LEAF_BYTES ((SLHDSA_SHA2_128S_LEAF_BITS + 7) / 8)


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_CRYPTO_SLHDSA_PARAMS_H
