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

#ifndef OPENSSL_HEADER_SLHDSA_H
#define OPENSSL_HEADER_SLHDSA_H

#include "CCryptoBoringSSL_base.h"

#if defined(__cplusplus)
extern "C" {
#endif


// SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES is the number of bytes in an
// SLH-DSA-SHA2-128s public key.
#define SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES 32

// SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES is the number of bytes in an
// SLH-DSA-SHA2-128s private key.
#define SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES 64

// SLHDSA_SHA2_128S_SIGNATURE_BYTES is the number of bytes in an
// SLH-DSA-SHA2-128s signature.
#define SLHDSA_SHA2_128S_SIGNATURE_BYTES 7856

// SLHDSA_SHA2_128S_generate_key generates a SLH-DSA-SHA2-128s key pair and
// writes the result to |out_public_key| and |out_private_key|.
OPENSSL_EXPORT void SLHDSA_SHA2_128S_generate_key(
    uint8_t out_public_key[SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES],
    uint8_t out_private_key[SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES]);

// SLHDSA_SHA2_128S_public_from_private writes the public key corresponding to
// |private_key| to |out_public_key|.
OPENSSL_EXPORT void SLHDSA_SHA2_128S_public_from_private(
    uint8_t out_public_key[SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES],
    const uint8_t private_key[SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES]);

// SLHDSA_SHA2_128S_sign slowly generates a SLH-DSA-SHA2-128s signature of |msg|
// using |private_key| and writes it to |out_signature|. The |context| argument
// is also signed over and can be used to include implicit contextual
// information that isn't included in |msg|. The same value of |context| must be
// presented to |SLHDSA_SHA2_128S_verify| in order for the generated signature
// to be considered valid. |context| and |context_len| may be |NULL| and 0 to
// use an empty context (this is common). It returns 1 on success and 0 if
// |context_len| is larger than 255.
OPENSSL_EXPORT int SLHDSA_SHA2_128S_sign(
    uint8_t out_signature[SLHDSA_SHA2_128S_SIGNATURE_BYTES],
    const uint8_t private_key[SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES],
    const uint8_t *msg, size_t msg_len, const uint8_t *context,
    size_t context_len);

// SLHDSA_SHA2_128S_verify verifies that |signature| is a valid
// SLH-DSA-SHA2-128s signature of |msg| by |public_key|. The value of |context|
// must equal the value that was passed to |SLHDSA_SHA2_128S_sign| when the
// signature was generated. It returns 1 if the signature is valid and 0
// otherwise.
OPENSSL_EXPORT int SLHDSA_SHA2_128S_verify(
    const uint8_t *signature, size_t signature_len,
    const uint8_t public_key[SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES],
    const uint8_t *msg, size_t msg_len, const uint8_t *context,
    size_t context_len);


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_SLHDSA_H
