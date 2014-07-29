// Spooky Hash
// A 128-bit noncryptographic hash, for checksums and table lookup
// By Bob Jenkins.  Public domain.

#pragma once

#include <precomp.h>

// SpookyHash: hash a single message in one call, produce 128-bit output

//number of UINT64's in internal state
#define OVS_SPOOKY_NUM_VARS     ((SIZE_T)12)

typedef struct _OVS_SPOOKY_DATA
{
    // unhashed data, for partial messages
    UINT64  data[2 * OVS_SPOOKY_NUM_VARS];

    // internal state of the hash
    UINT64  state[OVS_SPOOKY_NUM_VARS];

    // total length of the input so far
    SIZE_T  length;

    // length of unhashed data stashed in m_data*/
    BYTE    remainder;
}OVS_SPOOKY_DATA, *POVS_SPOOKY_DATA;

/***************************************************************************************/

//pMessage: message to hash
//length:   length of message in bytes
//pHash1:   in seed 1, out hash value 1
//pHash2:   in seed 2, out hash value 2
VOID Spooky_Hash128(_In_ const VOID* pMessage, SIZE_T length, _Inout_ UINT64* pHash1, _Inout_  UINT64* pHash2);

// Hash64: hash a single message in one call, return 64-bit output
//pMessage: message to hash
//length:   length of message in bytes
//seed:     seed
static __inline UINT64 Spooky_Hash64(_In_ const VOID* pMessage, SIZE_T length, UINT64 seed)
{
    UINT64 hash1 = seed;

    Spooky_Hash128(pMessage, length, &hash1, &seed);
    return hash1;
}

// Hash32:  hash a single message in one call, produce 32-bit output
//pMessage: message to hash
//length:   length of message in bytes
//seed:     seed
static __inline UINT32 Spooky_Hash32(_In_ const VOID* pMessage, SIZE_T length, UINT32 seed)
{
    UINT64 hash1 = seed, hash2 = seed;

    Spooky_Hash128(pMessage, length, &hash1, &hash2);
    return (UINT32)hash1;
}

// Init: initialize the context of a SpookyHash
//seed1: any 64-bit value will do, including 0
//seed2: different seeds produce independent hashes
VOID Spooky_Init(UINT64 seed1, UINT64 seed2, _Out_ OVS_SPOOKY_DATA* pData);

//Update: add a piece of a message to a SpookyHash state
//pMessage,  message fragment
//length: length of message fragment in bytes
VOID Spooky_Update(_In_ const VOID* pMessage, SIZE_T length, _Inout_ OVS_SPOOKY_DATA* pData);

// Final: compute the hash for the current SpookyHash state
// This does not modify the state; you can keep updating it afterward
// The result is the same as if SpookyHash() had been called with
// all the pieces concatenated into one message.
//
// pHash1: out only: first 64 bits of hash value.
// pHash2: out only: second 64 bits of hash value.
void Spooky_Final(UINT64* pHash1, UINT64* pHash2, _Inout_ OVS_SPOOKY_DATA* pData);

// left rotate a 64-bit value by k bytes
static __inline UINT64 Spooky_Rot64(UINT64 x, INT k)
{
    return (x << k) | (x >> (64 - k));
}

// This is used if the input is 96 bytes long or longer.
//
// The internal state is fully overwritten every 96 bytes.
// Every input bit appears to cause at least 128 bits of entropy
// before 96 other bytes are combined, when run forward or backward
//   For every input bit,
//   Two inputs differing in just that input bit
//   Where "differ" means xor or subtraction
//   And the base value is random
//   When run forward or backwards one Mix
// I tried 3 pairs of each; they all differed by at least 212 bits.
static __inline VOID Spooky_Mix(_In_ const UINT64* data, UINT64* pS0, UINT64* pS1, UINT64* pS2, UINT64* pS3, UINT64* pS4, UINT64* pS5, UINT64* pS6, UINT64* pS7,
    UINT64* pS8, UINT64* pS9, UINT64* pS10, UINT64* pS11)
{
    *pS0 += data[0];    *pS2 ^= *pS10;  *pS11 ^= *pS0;  *pS0 = Spooky_Rot64(*pS0, 11);     *pS11 += *pS1;
    *pS1 += data[1];    *pS3 ^= *pS11;  *pS0 ^= *pS1;   *pS1 = Spooky_Rot64(*pS1, 32);     *pS0 += *pS2;
    *pS2 += data[2];    *pS4 ^= *pS0;   *pS1 ^= *pS2;   *pS2 = Spooky_Rot64(*pS2, 43);     *pS1 += *pS3;
    *pS3 += data[3];    *pS5 ^= *pS1;   *pS2 ^= *pS3;   *pS3 = Spooky_Rot64(*pS3, 31);     *pS2 += *pS4;
    *pS4 += data[4];    *pS6 ^= *pS2;   *pS3 ^= *pS4;   *pS4 = Spooky_Rot64(*pS4, 17);     *pS3 += *pS5;
    *pS5 += data[5];    *pS7 ^= *pS3;   *pS4 ^= *pS5;   *pS5 = Spooky_Rot64(*pS5, 28);     *pS4 += *pS6;
    *pS6 += data[6];    *pS8 ^= *pS4;   *pS5 ^= *pS6;   *pS6 = Spooky_Rot64(*pS6, 39);     *pS5 += *pS7;
    *pS7 += data[7];    *pS9 ^= *pS5;   *pS6 ^= *pS7;   *pS7 = Spooky_Rot64(*pS7, 57);     *pS6 += *pS8;
    *pS8 += data[8];    *pS10 ^= *pS6;  *pS7 ^= *pS8;   *pS8 = Spooky_Rot64(*pS8, 55);     *pS7 += *pS9;
    *pS9 += data[9];    *pS11 ^= *pS7;  *pS8 ^= *pS9;   *pS9 = Spooky_Rot64(*pS9, 54);     *pS8 += *pS10;
    *pS10 += data[10];  *pS0 ^= *pS8;   *pS9 ^= *pS10;  *pS10 = Spooky_Rot64(*pS10, 22);   *pS9 += *pS11;
    *pS11 += data[11];  *pS1 ^= *pS9;   *pS10 ^= *pS11; *pS11 = Spooky_Rot64(*pS11, 46);   *pS10 += *pS0;
}

//
// Mix all 12 inputs together so that *pH0, *pH1 are a hash of them all.
//
// For two inputs differing in just the input bits
// Where "differ" means xor or subtraction
// And the base value is random, or a counting value starting at that bit
// The final result will have each bit of *pH0, *pH1 flip
// For every input bit,
// with probability 50 +- .3%
// For every pair of input bits,
// with probability 50 +- 3%
//
// This does not rely on the last Mix() call having already mixed some.
// Two iterations was almost good enough for a 64-bit result, but a
// 128-bit result is reported, so End() does three iterations.
//
static __inline VOID Spooky_EndPartial(UINT64* pH0, UINT64* pH1, UINT64* pH2, UINT64* pH3, UINT64* pH4, UINT64* pH5, UINT64* pH6, UINT64* pH7,
    UINT64* pH8, UINT64* pH9, UINT64* pH10, UINT64* pH11)
{
    *pH11 += *pH1;  *pH2 ^= *pH11;  *pH1 = Spooky_Rot64(*pH1, 44);
    *pH0 += *pH2;   *pH3 ^= *pH0;   *pH2 = Spooky_Rot64(*pH2, 15);
    *pH1 += *pH3;   *pH4 ^= *pH1;   *pH3 = Spooky_Rot64(*pH3, 34);
    *pH2 += *pH4;   *pH5 ^= *pH2;   *pH4 = Spooky_Rot64(*pH4, 21);
    *pH3 += *pH5;   *pH6 ^= *pH3;   *pH5 = Spooky_Rot64(*pH5, 38);
    *pH4 += *pH6;   *pH7 ^= *pH4;   *pH6 = Spooky_Rot64(*pH6, 33);
    *pH5 += *pH7;   *pH8 ^= *pH5;   *pH7 = Spooky_Rot64(*pH7, 10);
    *pH6 += *pH8;   *pH9 ^= *pH6;   *pH8 = Spooky_Rot64(*pH8, 13);
    *pH7 += *pH9;   *pH10 ^= *pH7;  *pH9 = Spooky_Rot64(*pH9, 38);
    *pH8 += *pH10;  *pH11 ^= *pH8;  *pH10 = Spooky_Rot64(*pH10, 53);
    *pH9 += *pH11;  *pH0 ^= *pH9;   *pH11 = Spooky_Rot64(*pH11, 42);
    *pH10 += *pH0;  *pH1 ^= *pH10;  *pH0 = Spooky_Rot64(*pH0, 54);
}

static __inline void Spooky_End(const UINT64 *data, UINT64* pH0, UINT64* pH1, UINT64* pH2, UINT64* pH3, UINT64* pH4, UINT64* pH5, UINT64* pH6,
    UINT64* pH7, UINT64* pH8, UINT64* pH9, UINT64* pH10, UINT64* pH11)
{
    pH0 += data[0];   pH1 += data[1];   pH2 += data[2];   pH3 += data[3];
    pH4 += data[4];   pH5 += data[5];   pH6 += data[6];   pH7 += data[7];
    pH8 += data[8];   pH9 += data[9];   pH10 += data[10]; pH11 += data[11];

    Spooky_EndPartial(pH0, pH1, pH2, pH3, pH4, pH5, pH6, pH7, pH8, pH9, pH10, pH11);
    Spooky_EndPartial(pH0, pH1, pH2, pH3, pH4, pH5, pH6, pH7, pH8, pH9, pH10, pH11);
    Spooky_EndPartial(pH0, pH1, pH2, pH3, pH4, pH5, pH6, pH7, pH8, pH9, pH10, pH11);
}

// The goal is for each bit of the input to expand into 128 bits of 
//   apparent entropy before it is fully overwritten.
//   n trials both set and cleared at least m bits of *pH0 *pH1 *pH2 *pH3
//   n: 2   m: 29
//   n: 3   m: 46
//   n: 4   m: 57
//   n: 5   m: 107
//   n: 6   m: 146
//   n: 7   m: 152
// when run forwards or backwards
// for all 1-bit and 2-bit diffs
// with diffs defined by either xor or subtraction
// with a base of all zeros plus a counter, or plus another bit, or random
static __inline VOID Spooky_ShortMix(UINT64* pH0, UINT64* pH1, UINT64* pH2, UINT64* pH3)
{
    *pH2 = Spooky_Rot64(*pH2, 50);  *pH2 += *pH3;  *pH0 ^= *pH2;
    *pH3 = Spooky_Rot64(*pH3, 52);  *pH3 += *pH0;  *pH1 ^= *pH3;
    *pH0 = Spooky_Rot64(*pH0, 30);  *pH0 += *pH1;  *pH2 ^= *pH0;
    *pH1 = Spooky_Rot64(*pH1, 41);  *pH1 += *pH2;  *pH3 ^= *pH1;
    *pH2 = Spooky_Rot64(*pH2, 54);  *pH2 += *pH3;  *pH0 ^= *pH2;
    *pH3 = Spooky_Rot64(*pH3, 48);  *pH3 += *pH0;  *pH1 ^= *pH3;
    *pH0 = Spooky_Rot64(*pH0, 38);  *pH0 += *pH1;  *pH2 ^= *pH0;
    *pH1 = Spooky_Rot64(*pH1, 37);  *pH1 += *pH2;  *pH3 ^= *pH1;
    *pH2 = Spooky_Rot64(*pH2, 62);  *pH2 += *pH3;  *pH0 ^= *pH2;
    *pH3 = Spooky_Rot64(*pH3, 34);  *pH3 += *pH0;  *pH1 ^= *pH3;
    *pH0 = Spooky_Rot64(*pH0, 5);   *pH0 += *pH1;  *pH2 ^= *pH0;
    *pH1 = Spooky_Rot64(*pH1, 36);  *pH1 += *pH2;  *pH3 ^= *pH1;
}

// Mix all 4 inputs together so that *pH0, *pH1 are a hash of them all.
//
// For two inputs differing in just the input bits
// Where "differ" means xor or subtraction
// And the base value is random, or a counting value starting at that bit
// The final result will have each bit of *pH0, *pH1 flip
// For every input bit,
// with probability 50 +- .3% (it is probably better than that)
// For every pair of input bits,
// with probability 50 +- .75% (the worst case is approximately that)
static __inline void Spooky_ShortEnd(UINT64* pH0, UINT64* pH1, UINT64* pH2, UINT64* pH3)
{
    *pH3 ^= *pH2;  *pH2 = Spooky_Rot64(*pH2, 15);  *pH3 += *pH2;
    *pH0 ^= *pH3;  *pH3 = Spooky_Rot64(*pH3, 52);  *pH0 += *pH3;
    *pH1 ^= *pH0;  *pH0 = Spooky_Rot64(*pH0, 26);  *pH1 += *pH0;
    *pH2 ^= *pH1;  *pH1 = Spooky_Rot64(*pH1, 51);  *pH2 += *pH1;
    *pH3 ^= *pH2;  *pH2 = Spooky_Rot64(*pH2, 28);  *pH3 += *pH2;
    *pH0 ^= *pH3;  *pH3 = Spooky_Rot64(*pH3, 9);   *pH0 += *pH3;
    *pH1 ^= *pH0;  *pH0 = Spooky_Rot64(*pH0, 47);  *pH1 += *pH0;
    *pH2 ^= *pH1;  *pH1 = Spooky_Rot64(*pH1, 54);  *pH2 += *pH1;
    *pH3 ^= *pH2;  *pH2 = Spooky_Rot64(*pH2, 32);  *pH3 += *pH2;
    *pH0 ^= *pH3;  *pH3 = Spooky_Rot64(*pH3, 25);  *pH0 += *pH3;
    *pH1 ^= *pH0;  *pH0 = Spooky_Rot64(*pH0, 63);  *pH1 += *pH0;
}

// Short is used for messages under 192 bytes in length
// Short has a low startup cost, the normal mode is good for long
// keys, the cost crossover is at about 192 bytes.  The two modes were
// held to the same quality bar.
//
// pMessage:    array of bytes, not necessarily aligned
// length:      length of message (in bytes)
// hHash1:      in the seed, out the hash value
// pHash2:      in the seed, out the hash value
VOID Spooky_Short(_In_ const VOID* pMessage, SIZE_T length, _Inout_ UINT64* pHash1, _Inout_ UINT64* pHash2);
