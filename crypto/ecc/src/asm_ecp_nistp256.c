/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_CURVE_NISTP256_ASM) && defined(HITLS_CRYPTO_NIST_ECC_ACCELERATE)

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "crypt_errno.h"
#include "crypt_bn.h"
#include "ecp_nistp256.h"
#include "crypt_ecc.h"
#include "ecc_local.h"
#include "bsl_err_internal.h"
#include "asm_ecp_nistp256.h"
#include "securec.h"

#if defined(HITLS_SIXTY_FOUR_BITS)
    // 1 is on the field with Montgomery, 1 * RR * R' mod P = R mod P = R - P
    static const Coord g_oneMont = {{
        0x0000000000000001,
        0xffffffff00000000,
        0xffffffffffffffff,
        0x00000000fffffffe
    }};
    static const Coord g_rrModP = {{
        0x0000000000000003,
        0xfffffffbffffffff,
        0xfffffffffffffffe,
        0x00000004fffffffd
    }};
#elif defined(HITLS_THIRTY_TWO_BITS)
    // 1 is on the field with Montgomery, 1 * RR * R' mod P = R mod P = R - P
    static const Coord g_oneMont = {{
        0x00000001,
        0x00000000,
        0x00000000,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xfffffffe,
        0x00000000
    }};
    static const Coord g_rrModP = {{
        0x00000003,
        0x00000000,
        0xffffffff,
        0xfffffffb,
        0xfffffffe,
        0xffffffff,
        0xfffffffd,
        0x00000004
    }};
#else
#error BN_UINT MUST be 4 or 8
#endif

// If the value is 0, all Fs are returned. If the value is not 0, 0 is returned.
static BN_UINT IsZero(const Coord *a)
{
    BN_UINT ret = a->value[0];
    for (uint32_t i = 1; i < P256_SIZE; i++) {
        ret |= a->value[i];
    }
    return BN_IsZeroUintConsttime(ret);
}

// r = cond == 0 ? r : a, the input parameter cond can only be 0 or 1.
// If cond is 0, the value remains unchanged. If cond is 1, copy a.
static void CopyConditional(Coord *r, const Coord *a, BN_UINT cond)
{
    BN_UINT mask1 = ~cond & (cond - 1);
    BN_UINT mask2 = ~mask1;

    for (uint32_t i = 0; i < P256_SIZE; i++) {
        r->value[i] = (r->value[i] & mask1) ^ (a->value[i] & mask2);
    }
}

// Jacobian affine -> Jacobian projection, (X,Y)->(X,Y,Z)
static void Affine2Jproj(P256_Point *r, const P256_AffinePoint *a, BN_UINT mask)
{
    for (uint32_t i = 0; i < P256_SIZE; i++) {
        r->x.value[i] = a->x.value[i] & mask;
        r->y.value[i] = a->y.value[i] & mask;
        r->z.value[i] = g_oneMont.value[i] & mask;
    }
}

// r = a^-1 mod p = a^(p-2) mod p
// p-2 = 0xffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff fffffffd
static void ECP256_ModInverse(Coord *r, const Coord *a)
{
    // a^(0x3), a^(0xc) = a^(0b1100), a^(0xf), a^(0xf0), a^(0xff)
    // a^(0xff00), a^(0xffff), a^(0xffff0000), a^(0xffffffff)
    Coord a3, ac, af, af0, a2f, a2f20, a4f, a4f40, a8f, ans;
    uint32_t i;
    // 0x3 = 0b11 = 0b10 + 0b01
    ECP256_Sqr(&a3, a);                 // a^2
    ECP256_Mul(&a3, &a3, a);            // a^3 = a^2 * a
    // 0xf = 0b1111 = 0b1100 + 0b11, 0b11->0b1100 requires *4, and the exponent*4(2^2) requires twice square operations
    ECP256_Sqr(&af, &a3);               // a^6  = (a^3)^2
    ECP256_Sqr(&ac, &af);               // a^12 = (a^3)^2 = a^(0xc)
    ECP256_Mul(&af, &ac, &a3);          // a^f  = a^15 = a^12 * a^3
    // 0xff = 0b11111111 = 0b11110000 + 0b1111, 0b1111->0b11110000 requires *16,
    // the exponent*16(2^4) requires 4 times square operations
    ECP256_Sqr(&a2f, &af);              // a^(0b11110)   = (a^f)^2
    ECP256_Sqr(&a2f, &a2f);             // a^(0b111100)  = (a^(0b11110))^2
    ECP256_Sqr(&a2f, &a2f);             // a^(0b1111000) = (a^(0b111100))^2
    ECP256_Sqr(&af0, &a2f);             // a^(0xf0)      = a^(0b11110000)   = (a^(0b1111000))^2
    ECP256_Mul(&a2f, &af0, &af);        // a^(0xff)      = a^(0xf0) * a^(0xf)
    // a^(0xffff)
    ECP256_Sqr(&a2f20, &a2f);
    for (i = 1; i < 8; i++) {           // need to left shift by 8 bits
        ECP256_Sqr(&a2f20, &a2f20);
    }
    // When the loop ends, &a2f20 = a^(0xff00)
    ECP256_Mul(&a4f, &a2f20, &a2f);     // a^(0xffff) = a^(0xff00) * a^(0xff)
    // a^(0xffffffff)
    ECP256_Sqr(&a4f40, &a4f);
    for (i = 1; i < 16; i++) {          // need to left shift by 16 bits
        ECP256_Sqr(&a4f40, &a4f40);
    }
    // When the loop ends, &a4f40 = a^(0xffff0000)
    ECP256_Mul(&a8f, &a4f40, &a4f);     // a^(0xffffffff) = a^(0xffff0000) * a^(0xffff)
    // a^(0xffffffff 00000001)
    ECP256_Sqr(&ans, &a8f);
    for (i = 1; i < 32; i++) {          // need to left shift by 32 bits
        ECP256_Sqr(&ans, &ans);
    }
    ECP256_Mul(&ans, &ans, a);          // a^(0xffffffff 00000001) = a^(0xffffffff 00000000) * a
    // a^(0xffffffff 00000001 00000000 00000000 00000000 ffffffff)
    for (i = 0; i < 32 * 4; i++) {      // need to left shift by 32 * 4 bits
        ECP256_Sqr(&ans, &ans);
    }
    ECP256_Mul(&ans, &ans, &a8f);
    // a^(0xffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff)
    for (i = 0; i < 32; i++) {          // need to left shift by 32 bits
        ECP256_Sqr(&ans, &ans);
    }
    ECP256_Mul(&ans, &ans, &a8f);
    // a^(0xffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff fffffffd)
    for (i = 0; i < 32; i++) {          // need to left shift by 32 bits
        ECP256_Sqr(&ans, &ans);
    }
    // a^(0xffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff 00000000)
    ECP256_Mul(&ans, &ans, &a4f40);     // a^(0xffff0000)
    ECP256_Mul(&ans, &ans, &a2f20);     // a^(0xff00)
    ECP256_Mul(&ans, &ans, &af0);       // a^(0xf0)
    ECP256_Mul(&ans, &ans, &ac);        // a^(0xc)
    ECP256_Mul(r, &ans, a);             // a^(0x1)
}

static int32_t ECP256_GetAffine(ECC_Point *r, const P256_Point *pt)
{
    Coord zInv3;
    Coord zInv2;
    Coord res_x;
    Coord res_y;
    int32_t ret;
    if (IsZero(&(pt->z)) != 0) {
        ret = CRYPT_ECC_POINT_AT_INFINITY;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ECP256_ModInverse(&zInv3, &(pt->z));        // zInv
    ECP256_Sqr(&zInv2, &zInv3);                 // zInv^2
    ECP256_Mul(&zInv3, &zInv2, &zInv3);         // zInv^3
    ECP256_Mul(&res_x, &(pt->x), &zInv2);       // xMont = x / (z^2)
    ECP256_Mul(&res_y, &(pt->y), &zInv3);       // yMont = y / (z^3)
    ECP256_FromMont(&res_x, &res_x);
    ECP256_FromMont(&res_y, &res_y);
    ret = BN_Array2BN(&r->x, res_x.value, P256_SIZE);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_Array2BN(&r->y, res_y.value, P256_SIZE);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BN_SetLimb(&r->z, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static void ECP256_P256Point2EccPoint(ECC_Point *r, const P256_Point *pt)
{
    Coord xTemp;
    Coord yTemp;
    Coord zTemp;
    ECP256_FromMont(&xTemp, &(pt->x));
    ECP256_FromMont(&yTemp, &(pt->y));
    ECP256_FromMont(&zTemp, &(pt->z));
    (void)BN_Array2BN(&r->x, xTemp.value, P256_SIZE);
    (void)BN_Array2BN(&r->y, yTemp.value, P256_SIZE);
    (void)BN_Array2BN(&r->z, zTemp.value, P256_SIZE);
}

static void ECP256_EccPoint2P256Point(P256_Point *r, const ECC_Point *pt)
{
    (void)BN_BN2Array(&pt->x, r->x.value, P256_SIZE);
    (void)BN_BN2Array(&pt->y, r->y.value, P256_SIZE);
    (void)BN_BN2Array(&pt->z, r->z.value, P256_SIZE);
    ECP256_Mul(&(r->x), &(r->x), &g_rrModP);
    ECP256_Mul(&(r->y), &(r->y), &g_rrModP);
    ECP256_Mul(&(r->z), &(r->z), &g_rrModP);
}

int32_t ECP256_Point2Affine(const ECC_Para *para, ECC_Point *r, const ECC_Point *pt)
{
    if (r == NULL || pt == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (para->id != CRYPT_ECC_NISTP256 || r->id != CRYPT_ECC_NISTP256 || pt->id != CRYPT_ECC_NISTP256) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    P256_Point temp;
    ECP256_EccPoint2P256Point(&temp, pt);
    return ECP256_GetAffine(r, &temp);
}

// The value of 'in' contains a maximum of six bits. The input parameter must be & 0b111111 in advance.
static uint32_t Recodew5(uint32_t in)
{
    // Shift rightwards by 5 bits to get the most significant bit, check whether the most significant bit is 1.
    uint32_t sign = (in >> 5) - 1;
    uint32_t data = (1 << 6) - 1 - in;      // (6 Ones)0b111111 - in
    data = (data & ~sign) | (in & sign);
    data = (data >> 1) + (data & 1);

    return (data << 1) + (~sign & 1);
}

// The value of 'in' contains a maximum of six bits. The input parameter must be & 0b11111111 in advance.
static uint32_t Recodew7(uint32_t in)
{
    // Shift rightwards by 7 bits to get the most significant bit, check whether the most significant bit is 1.
    uint32_t sign = (in >> 7) - 1;
    uint32_t data = (1 << 8) - 1 - in;      // (8 Ones)0b11111111 - in
    data = (data & ~sign) | (in & sign);
    data = (data >> 1) + (data & 1);

    return (data << 1) + (~sign & 1);
}

static void ECP256_PreCompWindow(P256_Point table[16], P256_Point *pt)
{
    P256_Point temp[4];
    ECP256_Scatterw5(table, pt, 1);
    ECP256_PointDouble(&temp[0], pt);                 // 2G
    ECP256_Scatterw5(table, &temp[0], 2);             // Discretely save temp[0] to the 2nd position of the table.
    ECP256_PointAdd(&temp[1], &temp[0], pt);          // temp[0] = 3G = 2G + G
    ECP256_Scatterw5(table, &temp[1], 3);             // Discretely saves temp[1] to the 3rd position of the table.
    ECP256_PointDouble(&temp[2], &temp[0]);           // temp[2] = 4G = 2G * 2
    ECP256_Scatterw5(table, &temp[2], 4);             // Discretely save temp[2] to the 4th position in the table.
    ECP256_PointAdd(&temp[3], &temp[2], pt);          // temp[3] = 5G = 4G + G = = temp[2] + pt
    ECP256_Scatterw5(table, &temp[3], 5);             // Discretely save temp[3] to the 5th position in the table.
    ECP256_PointDouble(&temp[0], &temp[1]);           // temp[0] = 6G = 3G * 2
    ECP256_Scatterw5(table, &temp[0], 6);             // Discretely save temp[0] to the 6th position in the table.
    ECP256_PointAdd(&temp[1], &temp[0], pt);          // temp[1] = 7G = 6G + G
    ECP256_Scatterw5(table, &temp[1], 7);             // Discretely save temp[1] to the 7th position in the table.
    ECP256_PointDouble(&temp[2], &temp[2]);           // temp[2] = 8G = 4G * 2
    ECP256_Scatterw5(table, &temp[2], 8);             // Discretely save temp[2] to the 8th position in the table.
    ECP256_PointDouble(&temp[3], &temp[3]);           // temp[3] = 10G = 5G * 2
    ECP256_Scatterw5(table, &temp[3], 10);            // Discretely save temp[3] to the 10th position in the table.
    ECP256_PointAdd(&temp[3], &temp[3], pt);          // temp[3] = 11G = 10G + G
    ECP256_Scatterw5(table, &temp[3], 11);            // Discretely save temp[3] to the 11th position in the table.
    ECP256_PointDouble(&temp[0], &temp[0]);           // temp[0] = 12G = 6G * 2
    ECP256_Scatterw5(table, &temp[0], 12);            // Discretely save temp[0] to the 12th position in the table.
    ECP256_PointAdd(&temp[3], &temp[2], pt);          // temp[3] = 9G = 8G + G = temp[2] + pt
    ECP256_Scatterw5(table, &temp[3], 9);             // Discretely save temp[3] to the 9th position in the table.
    ECP256_PointAdd(&temp[3], &temp[0], pt);          // temp[3] = 13G = 12G + G
    ECP256_Scatterw5(table, &temp[3], 13);            // Discretely save temp[3] to the 13th position of the table.
    ECP256_PointDouble(&temp[1], &temp[1]);           // temp[1] = 14G = 7G * 2
    ECP256_Scatterw5(table, &temp[1], 14);            // Discretely saves temp[1] to the 14th position of the table.
    ECP256_PointAdd(&temp[0], &temp[1], pt);          // temp[0] = 15G = 14G + G = temp[1] + pt
    ECP256_Scatterw5(table, &temp[0], 15);            // Discretely save temp[0] to the 15th position of the table.
    ECP256_PointDouble(&temp[1], &temp[2]);           // temp[1] = 16G = 8G * 2 = temp[2] * 2
    ECP256_Scatterw5(table, &temp[1], 16);            // Discretely saves temp[1] to the 16th position of the table.
}

static void CRYPT_ECP256_PointDouble5Times(P256_Point *r)
{
    ECP256_PointDouble(r, r);
    ECP256_PointDouble(r, r);
    ECP256_PointDouble(r, r);
    ECP256_PointDouble(r, r);
    ECP256_PointDouble(r, r);
}

// r = k*point
// Ensure that m is not empty and is in the range (0, n-1)
static void ECP256_WindowMul(P256_Point *r, const BN_BigNum *k, const ECC_Point *point)
{
    uint8_t kOctets[33] = {0}; // m big endian byte stream. Apply for 33 bytes and reserve one byte for the following offset.
    P256_Point table[16]; // The pre-computation window is 2 ^ (5 - 1) = 16 points
    P256_Point temp; // Apply for temporary space of two points.
    Coord tempY;
    (void)BN_Bn2BinFixZero(k, kOctets, sizeof(kOctets));

    ECP256_EccPoint2P256Point(&temp, point);

    ECP256_PreCompWindow(table, &temp);

    // The first byte is the first two bits of kOctets[1].
    // The subscript starts from 0. Therefore, it is bit 0 + 8 and bit 1 + 8 = 9.
    uint32_t scans = 9;
    uint32_t index;   // position of the byte to be scanned.
    // Number of bits to be shifted rightwards by the current byte.
    // Each byte needs to be moved backward by a maximum of 7 bits.
    uint32_t shift = 7 - (scans % 8);
    uint32_t w = 5;                     // Window size = 5
    // the recode mask, the window size is 5, thus the value is 6 bits, mask = 0b111111 = 0x3f
    uint32_t mask = (1u << (w + 1)) - 1;
    uint32_t wCode = kOctets[1];
    wCode = (wCode >> shift) & mask;
    wCode = Recodew5(wCode);
    ECP256_Gatherw5(&temp, table, wCode >> 1);
    (void)memcpy_s(r, sizeof(P256_Point), &temp, sizeof(P256_Point));

    // 5 bits is obtained each time. The total number of bits is 256 + 8 (1 byte reserved) = 264 bits.
    // Therefore, the last time can be scanned to 264-5 = 259 bits.
    while (scans < 259) {
        // Double the point for 5 times
        CRYPT_ECP256_PointDouble5Times(r);

        scans += w;                 // Number of bits in the next scan.
        index = scans / 8;          // Location of the byte to be scanned. (1 byte = 8 bits)
        // Number of bits to be shifted rightwards by the current byte.
        // Each byte needs to be moved backward by a maximum of 7 bits. (1 byte = 8 bits)
        shift = 7 - (scans % 8);
        // Shift the upper byte by 8 bits to left, concatenate the current byte, and then shift to get the current wCode
        wCode = kOctets[index] | (kOctets[index - 1] << 8);
        wCode = (wCode >> shift) & mask;
        wCode = Recodew5(wCode);
        ECP256_Gatherw5(&temp, table, wCode >> 1);
        ECP256_Neg(&tempY, &(temp.y));
        // If the least significant bit of the code is 1, plus -(wCode >> 1) times point.
        CopyConditional(&(temp.y), &tempY, wCode & 1);
        ECP256_PointAdd(r, r, &temp);
    }

    // Special processing of the last block
    CRYPT_ECP256_PointDouble5Times(r);

    wCode = kOctets[32]; // Obtain the last byte, that is, kOctets[32].
    wCode = (wCode << 1) & mask;
    wCode = Recodew5(wCode);
    ECP256_Gatherw5(&temp, table, wCode >> 1);
    ECP256_Neg(&tempY, &(temp.y));
    // If the least significant bit of the code is 1, plus -(wCode >> 1) times point.
    CopyConditional(&(temp.y), &tempY, wCode & 1);
    ECP256_PointAdd(r, r, &temp);
}

static void ComputeK1G(P256_Point *k1G, const BN_BigNum *k1)
{
    uint8_t kOctets[33] = {0}; // applies for 33 bytes and reserves one byte for the following offset. 256 bits are 32 bytes.
    Coord tempY;
    P256_AffinePoint k1GAffine;
    const ECP256_TableRow *preCompTable = NULL; // precompute window size is 2 ^(7 - 1) = 64
    preCompTable = ECP256_GetPreCompTable();
    // Offset during byte stream conversion. Ensure that the valid data of the mOctet is in the upper bits.
    (void)BN_Bn2BinFixZero(k1, kOctets, sizeof(kOctets));

    uint32_t w = 7; // Window size = 7
    // the recode mask, the window size is 7, thus 8 bits are used (one extra bit is the sign bit).
    // mask = 0b11111111 = 0xff
    uint32_t mask = (1u << (w + 1)) - 1;
    uint32_t wCode = (kOctets[32] << 1) & mask; // Last byte kOctets[32] is the least significant 7 bits.
    wCode = Recodew7(wCode);
    ECP256_Gatherw7(&k1GAffine, preCompTable[0], wCode >> 1);
    ECP256_Neg(&tempY, &(k1GAffine.y));
    // If the least significant bit of the code is 1, plus -(wCode >> 1) times point.
    CopyConditional(&(k1GAffine.y), &tempY, wCode & 1);
    // If the x and y coordinates of k1GAffine are both 0, then the infinity is all Fs; otherwise, the infinity is 0.
    BN_UINT infinity = IsZero(&(k1GAffine.x)) & IsZero(&(k1GAffine.y));
    Affine2Jproj(k1G, &k1GAffine, ~infinity);

    uint32_t scans = 0;
    uint32_t index, shift;
    // pre-computation table is table[37][64]. The table is queried every 7 bits (valid bits) of 256 bits. 256/7 = 36.57
    for (uint32_t i = 1; i < 37; i++) {
        scans += w;
        index = 32 - ((scans - 1) / 8); // The subscript of the last byte is 32, and 8 means 8 bits(1byte)
        shift = (scans - 1) % 8; // 8 means 8 bits(1byte)
        wCode = kOctets[index] | (kOctets[index - 1] << 8); // 8 means 8 bits(1byte)
        wCode = (wCode >> shift) & mask;
        wCode = Recodew7(wCode);
        ECP256_Gatherw7(&k1GAffine, preCompTable[i], wCode >> 1);
        ECP256_Neg(&tempY, &(k1GAffine.y));
        // If the least significant bit of the code is 1, plus -(wCode >> 1) times point.
        CopyConditional(&(k1GAffine.y), &tempY, wCode & 1);
        ECP256_AddAffine(k1G, k1G, &k1GAffine);
    }
}

static int32_t ECP256_PointMulCheck(ECC_Para *para, ECC_Point *r, const BN_BigNum *k, const ECC_Point *pt)
{
    bool flag = (para == NULL || r == NULL || k == NULL);
    uint32_t bits;
    if (flag) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != CRYPT_ECC_NISTP256 || r->id != CRYPT_ECC_NISTP256) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    if (pt != NULL) {
        if (pt->id != CRYPT_ECC_NISTP256) {
            BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
            return CRYPT_ECC_POINT_ERR_CURVE_ID;
        }
        // Special processing for the infinite point.
        if (BN_IsZero(&pt->z)) {
            BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
            return CRYPT_ECC_POINT_AT_INFINITY;
        }
    }
    bits = BN_Bits(k);
    if (bits > 256) {   // 256 is the number of bits in the curve mode
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_MUL_ERR_K_LEN);
        return CRYPT_ECC_POINT_MUL_ERR_K_LEN;
    }

    return CRYPT_SUCCESS;
}

// if pt == NULL, r = k * G, otherwise r = k * pt
int32_t ECP256_PointMul(ECC_Para *para, ECC_Point *r, const BN_BigNum *k, const ECC_Point *pt)
{
    P256_Point rTemp = {0};
    int32_t ret = ECP256_PointMulCheck(para, r, k, pt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    if (pt == NULL) {
        ComputeK1G(&rTemp, k);
    } else {
        ECP256_WindowMul(&rTemp, k, pt);
    }

    ECP256_P256Point2EccPoint(r, &rTemp);

    return ret;
}

static int32_t ECP256_PointMulAddCheck(
    ECC_Para *para, ECC_Point *r, const BN_BigNum *k1, const BN_BigNum *k2, const ECC_Point *pt)
{
    bool flag = (para == NULL || r == NULL || k1 == NULL || k2 == NULL || pt == NULL);
    uint32_t bits1, bits2;
    if (flag) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != CRYPT_ECC_NISTP256 || r->id != CRYPT_ECC_NISTP256 || pt->id != CRYPT_ECC_NISTP256) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    // Special processing of the infinite point.
    if (BN_IsZero(&pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }
    bits1 = BN_Bits(k1);
    bits2 = BN_Bits(k2);
    if (bits1 > 256 || bits2 > 256) {   // 256 is the number of bits in the curve mode
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_MUL_ERR_K_LEN);
        return CRYPT_ECC_POINT_MUL_ERR_K_LEN;
    }

    return CRYPT_SUCCESS;
}

// r = k1 * G + k2 * pt
int32_t ECP256_PointMulAdd(ECC_Para *para, ECC_Point *r, const BN_BigNum *k1, const BN_BigNum *k2,
    const ECC_Point *pt)
{
    int32_t ret = ECP256_PointMulAddCheck(para, r, k1, k2, pt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    P256_Point k2Pt;
    P256_Point k1G = {0};

    ECP256_WindowMul(&k2Pt, k2, pt);
    ComputeK1G(&k1G, k1);
    ECP256_PointAdd(&k1G, &k1G, &k2Pt);
    ECP256_P256Point2EccPoint(r, &k1G);
    return ret;
}
#endif /* defined(HITLS_CRYPTO_CURVE_NISTP256) && defined(HITLS_CRYPTO_NIST_USE_ACCEL) */
