// Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <CCryptoBoringSSL_asn1.h>

#include <CCryptoBoringSSL_err.h>
#include <CCryptoBoringSSL_mem.h>

// ASN1_ITEM version of dup: this follows the model above except we don't
// need to allocate the buffer. At some point this could be rewritten to
// directly dup the underlying structure instead of doing and encode and
// decode.
void *ASN1_item_dup(const ASN1_ITEM *it, void *x) {
  unsigned char *b = NULL;
  const unsigned char *p;
  long i;
  void *ret;

  if (x == NULL) {
    return NULL;
  }

  i = ASN1_item_i2d(reinterpret_cast<ASN1_VALUE *>(x), &b, it);
  if (b == NULL) {
    return NULL;
  }
  p = b;
  ret = ASN1_item_d2i(NULL, &p, i, it);
  OPENSSL_free(b);
  return ret;
}
