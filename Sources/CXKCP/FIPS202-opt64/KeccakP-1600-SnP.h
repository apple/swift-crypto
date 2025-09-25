/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.

Implementation by Gilles Van Assche and Ronny Van Keer, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

---

Please refer to SnP-documentation.h for more details.
*/

#ifndef _KeccakP_1600_SnP_h_
#define _KeccakP_1600_SnP_h_

#include <stddef.h>
#include <stdint.h>

#include "brg_endian.h"
#include "KeccakP-1600-opt64-config.h"

typedef struct {
    uint64_t A[25];
} KeccakP1600_plain64_state;

typedef KeccakP1600_plain64_state KeccakP1600_state;

#define KeccakP1600_implementation      "generic 64-bit optimized implementation (" KeccakP1600_implementation_config ")"
#define KeccakF1600_FastLoop_supported
#define KeccakP1600_12rounds_FastLoop_supported

#define KeccakP1600_StaticInitialize()
void KeccakP1600_Initialize(KeccakP1600_plain64_state *state);
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
#define KeccakP1600_AddByte(state, byte, offset) \
    ((unsigned char*)(state))[(offset)] ^= (byte)
#else
void KeccakP1600_AddByte(KeccakP1600_plain64_state *state, unsigned char data, unsigned int offset);
#endif
void KeccakP1600_AddBytes(KeccakP1600_plain64_state *state, const unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600_OverwriteBytes(KeccakP1600_plain64_state *state, const unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600_OverwriteWithZeroes(KeccakP1600_plain64_state *state, unsigned int byteCount);
void KeccakP1600_Permute_Nrounds(KeccakP1600_plain64_state *state, unsigned int nrounds);
void KeccakP1600_Permute_12rounds(KeccakP1600_plain64_state *state);
void KeccakP1600_Permute_24rounds(KeccakP1600_plain64_state *state);
void KeccakP1600_ExtractBytes(const KeccakP1600_plain64_state *state, unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600_ExtractAndAddBytes(const KeccakP1600_plain64_state *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length);
size_t KeccakF1600_FastLoop_Absorb(KeccakP1600_plain64_state *state, unsigned int laneCount, const unsigned char *data, size_t dataByteLen);
size_t KeccakP1600_12rounds_FastLoop_Absorb(KeccakP1600_plain64_state *state, unsigned int laneCount, const unsigned char *data, size_t dataByteLen);

#endif
