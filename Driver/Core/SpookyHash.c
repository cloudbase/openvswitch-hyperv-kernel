//
// SpookyHash: a 128-bit noncryptographic hash function
// By Bob Jenkins, public domain

#include "SpookyHash.h"

#define OVS_SPOOKY_ALLOW_UNALIGNED_READS 1

// size of the internal state
#define OVS_SPOOKY_BLOCK_SIZE   (OVS_SPOOKY_NUM_VARS * 8)

// size of buffer of unhashed data, in bytes
#define OVS_SPOOKY_BUFFER_SIZE         (2 * OVS_SPOOKY_BLOCK_SIZE)

// a constant which:
//  * is not zero
//  * is odd
//  * is a not-very-regular mix of 1's and 0's
//  * does not need any other special mathematical properties
#define OVS_SPOOKY_CONSTANT     ((UINT64)0xdeadbeefdeadbeefULL)

/***************************************************************************************/

// short hash ... it could be used on any message,
// but it's used by Spooky just for short messages.
VOID Spooky_Short(const VOID* pMessage, SIZE_T length, UINT64* pHash1, UINT64* pHash2)
{
    UINT64 buf[2 * OVS_SPOOKY_NUM_VARS];

    union
    {
        const BYTE  *p8;
        UINT32      *p32;
        UINT64      *p64;
        SIZE_T i;
    } u;

    SIZE_T remainder = length % 32;
    UINT64 a = *pHash1;
    UINT64 b = *pHash2;
    UINT64 c = OVS_SPOOKY_CONSTANT;
    UINT64 d = OVS_SPOOKY_CONSTANT;

    u.p8 = (const BYTE*)pMessage;

    if (!OVS_SPOOKY_ALLOW_UNALIGNED_READS && (u.i & 0x7))
    {
        RtlCopyMemory(buf, pMessage, length);
        u.p64 = buf;
    }

    if (length > 15)
    {
        const UINT64* pEnd = u.p64 + (length / 32) * 4;

        // handle all complete sets of 32 bytes
        for (; u.p64 < pEnd; u.p64 += 4)
        {
            c += u.p64[0];
            d += u.p64[1];

            Spooky_ShortMix(&a, &b, &c, &d);

            a += u.p64[2];
            b += u.p64[3];
        }

        //Handle the case of 16+ remaining bytes.
        if (remainder >= 16)
        {
            c += u.p64[0];
            d += u.p64[1];

            Spooky_ShortMix(&a, &b, &c, &d);

            u.p64 += 2;
            remainder -= 16;
        }
    }

    // Handle the last 0..15 bytes, and its length
    d += ((UINT64)length) << 56;
    switch (remainder)
    {
    case 15:
        d += ((UINT64)u.p8[14]) << 48;
    case 14:
        d += ((UINT64)u.p8[13]) << 40;
    case 13:
        d += ((UINT64)u.p8[12]) << 32;
    case 12:
        d += u.p32[2];
        c += u.p64[0];
        break;

    case 11:
        d += ((UINT64)u.p8[10]) << 16;
    case 10:
        d += ((UINT64)u.p8[9]) << 8;
    case 9:
        d += (UINT64)u.p8[8];
    case 8:
        c += u.p64[0];
        break;

    case 7:
        c += ((UINT64)u.p8[6]) << 48;
    case 6:
        c += ((UINT64)u.p8[5]) << 40;
    case 5:
        c += ((UINT64)u.p8[4]) << 32;
    case 4:
        c += u.p32[0];
        break;

    case 3:
        c += ((UINT64)u.p8[2]) << 16;
    case 2:
        c += ((UINT64)u.p8[1]) << 8;
    case 1:
        c += (UINT64)u.p8[0];
        break;

    case 0:
        c += OVS_SPOOKY_CONSTANT;
        d += OVS_SPOOKY_CONSTANT;
    }

    Spooky_ShortEnd(&a, &b, &c, &d);

    *pHash1 = a;
    *pHash2 = b;
}

// do the whole hash in one call
VOID Spooky_Hash128(const VOID* pMessage, SIZE_T length, UINT64* pHash1, UINT64* pHash2)
{
    UINT64 h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11;
    UINT64 buf[OVS_SPOOKY_NUM_VARS];
    UINT64* pEnd = NULL;
    SIZE_T remainder = 0;

    union
    {
        const BYTE  *p8;
        UINT64      *p64;
        SIZE_T      i;
    } u;

    if (length < OVS_SPOOKY_BUFFER_SIZE)
    {
        Spooky_Short(pMessage, length, pHash1, pHash2);
        return;
    }

    h0 = h3 = h6 = h9 = *pHash1;
    h1 = h4 = h7 = h10 = *pHash2;
    h2 = h5 = h8 = h11 = OVS_SPOOKY_CONSTANT;

    u.p8 = (const BYTE*)pMessage;
    pEnd = u.p64 + (length / OVS_SPOOKY_BLOCK_SIZE)*OVS_SPOOKY_NUM_VARS;

    // handle all whole OVS_SPOOKY_BLOCK_SIZE blocks of bytes
    if (OVS_SPOOKY_ALLOW_UNALIGNED_READS || ((u.i & 0x7) == 0))
    {
        while (u.p64 < pEnd)
        {
            Spooky_Mix(u.p64, &h0, &h1, &h2, &h3, &h4, &h5, &h6, &h7, &h8, &h9, &h10, &h11);

            u.p64 += OVS_SPOOKY_NUM_VARS;
        }
    }
    else
    {
        while (u.p64 < pEnd)
        {
            RtlCopyMemory(buf, u.p64, OVS_SPOOKY_BLOCK_SIZE);

            Spooky_Mix(buf, &h0, &h1, &h2, &h3, &h4, &h5, &h6, &h7, &h8, &h9, &h10, &h11);

            u.p64 += OVS_SPOOKY_NUM_VARS;
        }
    }

    // handle the last partial block of OVS_SPOOKY_BLOCK_SIZE bytes
    remainder = (length - ((const BYTE*)pEnd - (const BYTE*)pMessage));

    RtlCopyMemory(buf, pEnd, remainder);
    RtlZeroMemory(((BYTE*)buf) + remainder, OVS_SPOOKY_BLOCK_SIZE - remainder);

    ((BYTE*)buf)[OVS_SPOOKY_BLOCK_SIZE - 1] = (BYTE)remainder;

    // do some final mixing 
    Spooky_End(buf, &h0, &h1, &h2, &h3, &h4, &h5, &h6, &h7, &h8, &h9, &h10, &h11);
    *pHash1 = h0;
    *pHash2 = h1;
}



// init spooky state
VOID Spooky_Init(UINT64 seed1, UINT64 seed2, OVS_SPOOKY_DATA* pData)
{
    RtlZeroMemory(pData, sizeof(OVS_SPOOKY_DATA));

    pData->state[0] = seed1;
    pData->state[1] = seed2;
}


// add a message fragment to the state
VOID Spooky_Update(const VOID* pMessage, SIZE_T length, OVS_SPOOKY_DATA* pData)
{
    UINT64 h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11;
    SIZE_T newLength = length + pData->remainder;
    BYTE  remainder = 0;
    const UINT64 *pEnd = NULL;

    union
    {
        const BYTE  *p8;
        UINT64      *p64;
        SIZE_T      i;
    } u;

    // Is this pMessage fragment too short?  If it is, stuff it away.
    if (newLength < OVS_SPOOKY_BUFFER_SIZE)
    {
        RtlCopyMemory(&((BYTE*)pData->data)[pData->remainder], pMessage, length);

        pData->length = length + pData->length;
        pData->remainder = (BYTE)newLength;
        return;
    }

    // init the variables
    if (pData->length < OVS_SPOOKY_BUFFER_SIZE)
    {
        h0 = h3 = h6 = h9 = pData->state[0];
        h1 = h4 = h7 = h10 = pData->state[1];
        h2 = h5 = h8 = h11 = OVS_SPOOKY_CONSTANT;
    }
    else
    {
        h0 = pData->state[0];
        h1 = pData->state[1];
        h2 = pData->state[2];
        h3 = pData->state[3];
        h4 = pData->state[4];
        h5 = pData->state[5];
        h6 = pData->state[6];
        h7 = pData->state[7];
        h8 = pData->state[8];
        h9 = pData->state[9];
        h10 = pData->state[10];
        h11 = pData->state[11];
    }

    pData->length = length + pData->length;

    // if we've got anything stuffed away, use it now
    if (pData->remainder)
    {
        BYTE prefix = OVS_SPOOKY_BUFFER_SIZE - pData->remainder;

        RtlCopyMemory(&(((BYTE*)pData->data)[pData->remainder]), pMessage, prefix);

        u.p64 = pData->data;

        Spooky_Mix(u.p64, &h0, &h1, &h2, &h3, &h4, &h5, &h6, &h7, &h8, &h9, &h10, &h11);
        Spooky_Mix(&u.p64[OVS_SPOOKY_NUM_VARS], &h0, &h1, &h2, &h3, &h4, &h5, &h6, &h7, &h8, &h9, &h10, &h11);

        u.p8 = ((const BYTE*)pMessage) + prefix;
        length -= prefix;
    }
    else
    {
        u.p8 = (const BYTE*)pMessage;
    }

    // handle all whole blocks of OVS_SPOOKY_BLOCK_SIZE bytes
    pEnd = u.p64 + (length / OVS_SPOOKY_BLOCK_SIZE)*OVS_SPOOKY_NUM_VARS;
    remainder = (BYTE)(length - ((const BYTE*)pEnd - u.p8));

    if (OVS_SPOOKY_ALLOW_UNALIGNED_READS || (u.i & 0x7) == 0)
    {
        while (u.p64 < pEnd)
        {
            Spooky_Mix(u.p64, &h0, &h1, &h2, &h3, &h4, &h5, &h6, &h7, &h8, &h9, &h10, &h11);

            u.p64 += OVS_SPOOKY_NUM_VARS;
        }
    }
    else
    {
        while (u.p64 < pEnd)
        {
            RtlCopyMemory(pData->data, u.p8, OVS_SPOOKY_BLOCK_SIZE);

            Spooky_Mix(pData->data, &h0, &h1, &h2, &h3, &h4, &h5, &h6, &h7, &h8, &h9, &h10, &h11);

            u.p64 += OVS_SPOOKY_NUM_VARS;
        }
    }

    // stuff away the last few bytes
    pData->remainder = remainder;
    RtlCopyMemory(pData->data, pEnd, remainder);

    // stuff away the variables
    pData->state[0] = h0;
    pData->state[1] = h1;
    pData->state[2] = h2;
    pData->state[3] = h3;
    pData->state[4] = h4;
    pData->state[5] = h5;
    pData->state[6] = h6;
    pData->state[7] = h7;
    pData->state[8] = h8;
    pData->state[9] = h9;
    pData->state[10] = h10;
    pData->state[11] = h11;
}


// report the hash for the concatenation of all message fragments so far
VOID Spooky_Final(UINT64* pHash1, UINT64* pHash2, OVS_SPOOKY_DATA* pData)
{
    // init the variables
    if (pData->length < OVS_SPOOKY_BUFFER_SIZE)
    {
        *pHash1 = pData->state[0];
        *pHash2 = pData->state[1];

        Spooky_Short(pData->data, pData->length, pHash1, pHash2);
        return;
    }

    const UINT64 *data = (const UINT64 *)pData->data;
    BYTE remainder = pData->remainder;

    UINT64 h0 = pData->state[0];
    UINT64 h1 = pData->state[1];
    UINT64 h2 = pData->state[2];
    UINT64 h3 = pData->state[3];
    UINT64 h4 = pData->state[4];
    UINT64 h5 = pData->state[5];
    UINT64 h6 = pData->state[6];
    UINT64 h7 = pData->state[7];
    UINT64 h8 = pData->state[8];
    UINT64 h9 = pData->state[9];
    UINT64 h10 = pData->state[10];
    UINT64 h11 = pData->state[11];

    if (remainder >= OVS_SPOOKY_BLOCK_SIZE)
    {
        // pData->data can contain two blocks; handle any whole first block
        Spooky_Mix(data, &h0, &h1, &h2, &h3, &h4, &h5, &h6, &h7, &h8, &h9, &h10, &h11);

        data += OVS_SPOOKY_NUM_VARS;
        remainder -= OVS_SPOOKY_BLOCK_SIZE;
    }

    // mix in the last partial block, and the length mod OVS_SPOOKY_BLOCK_SIZE
    RtlZeroMemory(&((BYTE*)data)[remainder], (OVS_SPOOKY_BLOCK_SIZE - remainder));

    ((BYTE*)data)[OVS_SPOOKY_BLOCK_SIZE - 1] = remainder;

    // do some final mixing
    Spooky_End(data, &h0, &h1, &h2, &h3, &h4, &h5, &h6, &h7, &h8, &h9, &h10, &h11);

    *pHash1 = h0;
    *pHash2 = h1;
}