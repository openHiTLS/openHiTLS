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
#ifdef HITLS_CRYPTO_SM9

#include "sm9.h"
#include "sm9_curve.h"
#include "sm9_pairing.h"
#include "sm9_fp.h"
#include "crypt_util_rand.h"

#include <memory.h>

/***************************Compiler-Switches**********************************/

#define SM9_ALG_RND_ENABLE

#define SM9_PAIR_ENABLE

#define    SM9_SIG_SYS_ENABLE
#define SM9_SIG_USR_ENABLE

#define SM9_ENC_SYS_ENABLE
#define SM9_ENC_USR_ENABLE

#define SM9_KEYEX_ENABLE

#define SM9_HByteLen        40
#define SM9_HWordLen        (SM9_HByteLen/4)

#define    SM9_C1_ByteLen        (2*BNByteLen)

#define SM9_C3_ByteLen        (BNByteLen)

#define    SM9_Alg_Pair_Mont(pG, pP1, pP2)    SM9_Pairing_R_Ate(pG, pP1, pP2)

/*******************************Static Global *********************************/
static uint8_t    SM9_HID_Sign[1]    = {0x01};
static uint8_t    SM9_HID_Enc[1]    = {0x03};

static uint8_t    g_RandBuf[BNByteLen] __attribute__((used));

/******************************************************************************/
/*                    SM3 Adaptation Layer for SM9                           */
/******************************************************************************/

// Forward declarations from SM3 library
extern int32_t CRYPT_SM3_Update(void *ctx, const uint8_t *in, uint32_t len);
extern int32_t CRYPT_SM3_Final(void *ctx, uint8_t *out, uint32_t *outLen);

void SM9_Hash_Init(SM9_Hash_Ctx *ctx)
{
    // Manual initialization following CRYPT_SM3_Init logic
    memset(&ctx->sm3State, 0, sizeof(SM9_CRYPT_SM3_Ctx));

    // GM/T 0004-2012 chapter 4.1 - SM3 initial values
    ctx->sm3State.h[0] = 0x7380166F;
    ctx->sm3State.h[1] = 0x4914B2B9;
    ctx->sm3State.h[2] = 0x172442D7;
    ctx->sm3State.h[3] = 0xDA8A0600;
    ctx->sm3State.h[4] = 0xA96F30BC;
    ctx->sm3State.h[5] = 0x163138AA;
    ctx->sm3State.h[6] = 0xE38DEE4D;
    ctx->sm3State.h[7] = 0xB0FB0E4E;
}

void SM9_Hash_Update(SM9_Hash_Ctx *ctx, const unsigned char *data, unsigned int len)
{
    CRYPT_SM3_Update(&ctx->sm3State, data, len);
}

void SM9_Hash_Final(SM9_Hash_Ctx *ctx, unsigned char *digest)
{
    uint32_t outLen = 32;
    CRYPT_SM3_Final(&ctx->sm3State, digest, &outLen);
}

void SM9_Hash_Final_and_Xor(SM9_Hash_Ctx *ctx, unsigned char *pbXor, unsigned char *pbMsg)
{
    unsigned char digest[32];
    unsigned int i;

    uint32_t outLen = 32;
    CRYPT_SM3_Final(&ctx->sm3State, digest, &outLen);

    // XOR the digest with the input message
    for (i = 0; i < 32; i++) {
        pbXor[i] = digest[i] ^ pbMsg[i];
    }
}

void SM9_Hash_Data(const unsigned char *data, unsigned int len, unsigned char *digest)
{
    SM9_Hash_Ctx ctx;
    SM9_Hash_Init(&ctx);
    SM9_Hash_Update(&ctx, data, len);
    SM9_Hash_Final(&ctx, digest);
}

/******************************************************************************/
/*                    Random Number Generation for SM9                       */
/******************************************************************************/

void sm9_rand(unsigned char *p, int len)
{
    // Use library's cryptographic random number generator
    (void)CRYPT_Rand(p, (uint32_t)len);
}

/******************************************************************************/

void _ibc_alg_rand(unsigned char *r, unsigned int len)
{
    unsigned int i;

    for (i = 0; i < len; i++)
        *r++ = i;
}

static void _ibc_write_fpbytes(uint8_t *dst, uint32_t *src)
{
    int32_t    bytelen;
    BNToByte(src, BNWordLen, dst, &bytelen);
}

static void _sm9_hash_h(uint32_t *pwH, uint8_t tag, const uint8_t * msg, uint32_t mlen, uint8_t *add, uint32_t alen)
{
    SM9_Hash_Ctx    ctx;
    uint8_t    ct[4] = {0x00, 0x00, 0x00, 0x01};
    uint8_t    Ha[2*BNByteLen];
    uint32_t    pwHa[SM9_HWordLen+1];
    uint32_t pwN1[BNWordLen];
    // U64 carry = 0;
    int i;

    for (i = 0; i < 2; i++)
    {
        SM9_Hash_Init(&ctx);
        SM9_Hash_Update(&ctx, &tag, 1);
        SM9_Hash_Update(&ctx, msg, mlen);
        if (add)
            SM9_Hash_Update(&ctx, add, alen);
        SM9_Hash_Update(&ctx, ct, 4);
        SM9_Hash_Final(&ctx, Ha + i * BNByteLen);
        ct[3]++;
    }

    ByteToBN(Ha, SM9_HByteLen, pwHa, SM9_HWordLen);
    pwHa[SM9_HWordLen] = 0x00000000;

    // h=(Ha mod (n-1))+1
    bn_sub_int(pwN1, sm9_sys_para.EC_N, 1, BNWordLen);
    BN_Mod_Basic(pwH, BNWordLen, pwHa, SM9_HWordLen, pwN1, BNWordLen);
    bn_add_int(pwH, pwH, 1, BNWordLen);
}

static void SM9_Hash_H1(uint32_t *pwH, const uint8_t *msg, uint32_t mlen, uint8_t *add, uint32_t alen)
{
    _sm9_hash_h(pwH, 0x01, msg, mlen, add, alen);
}

static void SM9_Hash_H2(uint32_t *pwH, const uint8_t *msg, uint32_t mlen, uint8_t *add, uint32_t alen)
{
    _sm9_hash_h(pwH, 0x02, msg, mlen, add, alen);
}

/******************************************************************************/

SM9_API int SM9_Alg_GetVersion()
{
    int ret = 0;
    unsigned char a = 1;
    unsigned char b = 1;
    unsigned char c = 0;

#ifdef SM9_ALG_RND_ENABLE
    ret |= 0x01;
#endif // SM9_ALG_RND_ENABLE
#ifdef SM9_PAIR_ENABLE
    ret |= 0x02;
#endif // SM9_PAIR_ENABLE
#ifdef SM9_SIG_SYS_ENABLE
    ret |= 0x08;
#endif // SM9_SIG_SYS_ENABLE
#ifdef SM9_SIG_USR_ENABLE
    ret |= 0x04;
#endif // SM9_SIG_USR_ENABLE
#ifdef SM9_ENC_SYS_ENABLE
    ret |= 0x80;
#endif // SM9_ENC_SYS_ENABLE
#ifdef SM9_ENC_USR_ENABLE
    ret |= 0x40;
#endif // SM9_ENC_USR_ENABLE

    ret += (a << 24) + (b << 16) + (c << 8);

    return ret;
}

SM9_API int SM9_Alg_Pair(unsigned char *g, unsigned char *p1, unsigned char *p2)
{
#ifdef    SM9_PAIR_ENABLE
    SM9_ECP_A    Ecp_P1;
    SM9_ECP2_A    Ecp2_P2;
    SM9_Fp12        Fp12_G;

    // Read ecpoint P1 and convert to MontMode
    SM9_Ecp_A_ReadBytes(&Ecp_P1, p1);
    // Read ecpoint P2 and convert to MontMode
    SM9_Ecp2_A_ReadBytes(&Ecp2_P2, p2);
    // Compute pairing
    SM9_Alg_Pair_Mont(&Fp12_G, &Ecp_P1, &Ecp2_P2);
    // Output to bytes
    SM9_Fp12_WriteBytes(g, &Fp12_G);

    return SM9_OK;
#else
    return SM9_ERR_UNSUPPORT;
#endif /* SM9_PAIR_ENABLE */
}

SM9_API int SM9_Get_Sig_G(unsigned char *g, unsigned char *mpk)
{
    return SM9_Alg_Pair(g, g_SM9_G1, mpk);
}

SM9_API int SM9_Get_Enc_G(unsigned char *g, unsigned char *mpk)
{
    return SM9_Alg_Pair(g, mpk, g_SM9_G2);
}

SM9_API int SM9_Alg_MSKG(unsigned char *ks, unsigned char *mpk)
{
#ifdef    SM9_SIG_SYS_ENABLE
    uint32_t                BN_SK[BNWordLen];
    SM9_ECP2_A    Point_PK;

    // Read System PriKey to BN
    SM9_Bn_ReadBytes(BN_SK, ks);
    // Genarate System PubKey(in APoint MontMode)
    SM9_Ecp2_KP(&Point_PK, &sm9_sys_para.EC_Fp2_G_Mont, BN_SK);
    // Convert System PubKey to bytes(in NormMode)
    SM9_Ecp2_A_WriteBytes(mpk, &Point_PK);

    return SM9_OK;
#else
    return SM9_ERR_UNSUPPORT;
#endif /* SM9_SIG_SYS_ENABLE */
}

SM9_API int SM9_Alg_USKG(const unsigned char *id, unsigned int ilen, unsigned char *ks, unsigned char *ds)
{
#ifdef    SM9_SIG_SYS_ENABLE
    uint32_t                BN_t1[BNWordLen];
    uint32_t                BN_t2[BNWordLen];
    SM9_ECP_A    Ecp_ds;

    // Read System PriKey to BN
    SM9_Bn_ReadBytes(BN_t2, ks);

    // Compute t1 = H1(IDA||hid, N)+ks
    SM9_Hash_H1(BN_t1, id, ilen, SM9_HID_Sign, 1);
    SM9_Fn_Add(BN_t1, BN_t1, BN_t2);
    // Check t1 != 0
    if (SM9_Bn_IsZero(BN_t1))
        return SM9_ERR_ID_UNUSEABLE;
    // Compute t2 = ks*(t1^-1)
    BN_GetInv_Mont(BN_t1, BN_t1, sm9_sys_para.EC_N, sm9_sys_para.N_Mc, sm9_sys_para.N_R2, sm9_sys_para.wsize);
    bn_mont_mul(BN_t2, BN_t1, BN_t2, sm9_sys_para.EC_N, sm9_sys_para.N_Mc, sm9_sys_para.wsize);
    // Compute ds = [t2]P1
    SM9_Ecp_KP(&Ecp_ds, &sm9_sys_para.EC_Fp_G_Mont, BN_t2);

    // Convert User PriKey to bytes(in NormMode)
    SM9_Ecp_A_WriteBytes(ds, &Ecp_ds);

    return SM9_OK;
#else
    return SM9_ERR_UNSUPPORT;
#endif /* SM9_SIG_SYS_ENABLE */
}

#ifdef    SM9_SIG_USR_ENABLE
int _sm9_alg_sign(
    const unsigned char *msg, unsigned int mlen,
    const unsigned char *ds, unsigned char *r,
    const unsigned char *g, const unsigned char *mpk,
    uint32_t *BN_h, SM9_ECP_A *Ecp_s)
{
    uint32_t                BN_r[BNWordLen];
    uint8_t                pbW[12 * BNByteLen];
    SM9_Fp12        Fp12_g;
    SM9_ECP2_A    Ecp2_P;

    // Read Random number r(in NormMode)
    SM9_Bn_ReadBytes(BN_r, r);

    SM9_Fn_LastRes(BN_r);

    while(SM9_Bn_IsZero(BN_r)==1){
        sm9_rand(r,BNByteLen);
        SM9_Bn_ReadBytes(BN_r, r);
        SM9_Fn_LastRes(BN_r);
    }

    // Get System Element g and compute g^r
    if (g)//If g is given
    {
        // Read g from input and convert to MontMode
        SM9_Fp12_ReadBytes(&Fp12_g, g);
        // w = g^r
        SM9_Fp12_Exp(&Fp12_g, &Fp12_g, BN_r);
    }
    else//If g is not given
    {
        // Read Ppub from input
        SM9_Ecp2_A_ReadBytes(&Ecp2_P, mpk);
        // Compute w = e(r*P1, Ppub)
        SM9_Ecp_KP(Ecp_s, &sm9_sys_para.EC_Fp_G_Mont, BN_r);
        SM9_Alg_Pair_Mont(&Fp12_g, Ecp_s, &Ecp2_P);
    }
    SM9_Fp12_WriteBytes(pbW, &Fp12_g);

    // h = H2(M||w, N)
    SM9_Hash_H2(BN_h, msg, mlen, pbW, 12 * BNByteLen);

    // l = (r-h) mod N (l should not be zero)
    SM9_Fn_Sub(BN_r, BN_r, BN_h);
    if (SM9_Bn_IsZero(BN_r))
        return SM9_ERR_RND_UNUSEABLE;
    // Read User Prikey and convert to MontMode
    SM9_Ecp_A_ReadBytes(Ecp_s, ds);
    // S = l * dsA
    SM9_Ecp_KP(Ecp_s, Ecp_s, BN_r);

    return SM9_OK;
}
#endif /* SM9_SIG_USR_ENABLE */

SM9_API int SM9_Sign(
    unsigned int  opt,
    const unsigned char *msg,
    unsigned int  mlen,
    const unsigned char *ds,
    unsigned char *r,
    const unsigned char *g,
    const unsigned char *mpk,
    unsigned char *sign,
    unsigned int  *slen)
{
#ifdef    SM9_SIG_USR_ENABLE
    // Signature buf
    uint32_t                BN_h[BNWordLen];
    SM9_ECP_A    Ecp_s;
    int ret;
    int len;

#ifndef SM9_ALG_RND_ENABLE
    r = g_RandBuf;
    _ibc_alg_rand(r, BNByteLen);
#endif // SM9_ALG_RND_ENABLE

    ret = _sm9_alg_sign(msg, mlen, ds, r, g, mpk, BN_h, &Ecp_s);
    if (ret != SM9_OK)
        return ret;

    // Output Signature to bytes
    _ibc_write_fpbytes(sign, BN_h);
    len = SM9_Fp_ECP_A_WriteBytesWithPC(sign + sm9_sys_para.wsize*WordByteLen, opt, &Ecp_s);
    if (len < 0)
        return SM9_ERR_BAD_INPUT;
    *slen = len + sm9_sys_para.wsize*WordByteLen;

    return SM9_OK;
#else
    return SM9_ERR_UNSUPPORT;
#endif /* SM9_SIG_USR_ENABLE */
}

SM9_API int SM9_Alg_Sign(const unsigned char *msg, unsigned int mlen,
    const unsigned char *ds, unsigned char *r,
    const unsigned char *g, const unsigned char *mpk,
    unsigned char *sign)
{
    unsigned int slen;
    return SM9_Sign(SM9_OPT_DM_MODE0, msg, mlen, ds, r, g, mpk, sign, &slen);
}

#ifdef    SM9_SIG_USR_ENABLE
static int _sm9_alg_vefiry(
    const unsigned char *msg,    unsigned int mlen,
    const unsigned char *id,    unsigned int ilen,
    const unsigned char *g,    const unsigned char *mpk,
    uint32_t *BN_h, SM9_ECP_A *Ecp_s)
{
    SM9_Fp12        Fp12_g;
    SM9_Fp12        Fp12_u;
    uint8_t                pbW[12 * BNByteLen];

    // uint32_t                BN_h[BNWordLen];
    // SM9_ECP_A    Ecp_s;
    uint32_t                BN_h1[BNWordLen];
    SM9_ECP2_A    Ecp2_P;

    SM9_ECP2_J    Ecp2_J;

    SM9_ECP_J    Ecp_J;
    SM9_ECP_A    Ecp_A;

    // Read System PubKey to JPoint in MontMode
    SM9_Ecp2_A_ReadBytes(&Ecp2_P, mpk);

    // h1 = H1(IDA||hid, N)
    SM9_Hash_H1(BN_h1, id, ilen, SM9_HID_Sign, 1);

    // Get System Element g and convert to MontMode
    if (g)
    {//Read from input
        SM9_Fp12_ReadBytes(&Fp12_g, g);
        // t = g^h
        SM9_Fp12_Exp(&Fp12_g, &Fp12_g, BN_h);

        // P = [h1]P2 + Ppub-s
        SM9_Ecp2_A_ToJ(&Ecp2_J, &Ecp2_P);
        SM9_Ecp2_KP(&Ecp2_P, &sm9_sys_para.EC_Fp2_G_Mont, BN_h1);
        SM9_Ecp2_J_AddA(&Ecp2_J, &Ecp2_J, &Ecp2_P);
        SM9_Ecp2_J_ToA(&Ecp2_P, &Ecp2_J);
        // u = e(S', P)
        SM9_Alg_Pair_Mont(&Fp12_u, Ecp_s, &Ecp2_P);
    }
    else
    {//Compute by input
        // t = e([h]P1 + S, Ppub-s)
        SM9_Ecp_KP(&Ecp_A, &sm9_sys_para.EC_Fp_G_Mont, BN_h);
        SM9_Ecp_A_ToJ(&Ecp_J, &Ecp_A);
        SM9_Ecp_J_AddA(&Ecp_J, &Ecp_J, Ecp_s);
        SM9_Ecp_J_ToA(&Ecp_A, &Ecp_J);
        SM9_Alg_Pair_Mont(&Fp12_g, &Ecp_A, &Ecp2_P);

        // u = e([h1]S, P2)
        SM9_Ecp_KP(Ecp_s, Ecp_s, BN_h1);
        SM9_Alg_Pair_Mont(&Fp12_u, Ecp_s, &sm9_sys_para.EC_Fp2_G_Mont);
    }

    // w' = u * t
    SM9_Fp12_Mul(&Fp12_g, &Fp12_g, &Fp12_u);
    SM9_Fp12_WriteBytes(pbW, &Fp12_g);
    // h2 = H2(M'||w', N)
    SM9_Hash_H2(BN_h1, msg, mlen, pbW, 12 * BNByteLen);
    // Verify h2 ?= h
    if (bn_equal(BN_h1, BN_h, BNWordLen))
        return SM9_OK;
    return SM9_ERR_VERIFY_FAILED;
}
#endif /* SM9_SIG_USR_ENABLE */

SM9_API int SM9_Verify(
    unsigned int  opt,
    const unsigned char *msg,
    unsigned int  mlen,
    const unsigned char *id,
    unsigned int  ilen,
    const unsigned char *g,
    const unsigned char *mpk,
    const unsigned char *sign,
    unsigned char slen)
{
    int ret;
    uint32_t                BN_h[BNWordLen];
    SM9_ECP_A    Ecp_s;

    if ((opt == SM9_OPT_DM_MODE1) || (opt == SM9_OPT_DM_MODE3))
    {
        if (slen != SM9_SIGNATURE_BYTES + 1)
            return SM9_ERR_BAD_INPUT;
    }
    else if (opt == SM9_OPT_DM_MODE2)
    {
        if (slen != SM9_SIGNATURE_BYTES - SM9_CURVE_MODULE_BYTES + 1)
            return SM9_ERR_BAD_INPUT;
    }
    else
    {
        if (slen != SM9_SIGNATURE_BYTES)
            return SM9_ERR_BAD_INPUT;
    }

    // Read Signature(h,s) and convert s to MontMode
    SM9_Bn_ReadBytes(BN_h, sign);
    sign += sm9_sys_para.wsize*WordByteLen;
    if (SM9_Fp_ECP_A_ReadBytesWithPC(&Ecp_s, opt, sign))
        return -1;

    ret = _sm9_alg_vefiry(msg, mlen, id, ilen, g, mpk, BN_h, &Ecp_s);

    return ret;
}

SM9_API int SM9_Alg_Verify(
    const unsigned char *msg,
    unsigned int mlen,
    const unsigned char *id,
    unsigned int ilen,
    const unsigned char *g,
    const unsigned char *mpk,
    const unsigned char *sign)
{
    return SM9_Verify(SM9_OPT_DM_MODE0, msg, mlen, id, ilen, g, mpk, sign, SM9_SIGNATURE_BYTES);
}

SM9_API int SM9_Alg_MEKG(unsigned char *ke, unsigned char *mpk)
{
#ifdef    SM9_ENC_SYS_ENABLE
    uint32_t            BN_SK[BNWordLen];
    SM9_ECP_A    Point_PK;

    // Read System PriKey to BN
    SM9_Bn_ReadBytes(BN_SK, ke);
    // Genarate System PubKey(in APoint MontMode)
    SM9_Ecp_KP(&Point_PK, &sm9_sys_para.EC_Fp_G_Mont, BN_SK);
    // Convert System PubKey to bytes(in NormMode)
    SM9_Ecp_A_WriteBytes(mpk, &Point_PK);

    return SM9_OK;
#else
    return SM9_ERR_UNSUPPORT;
#endif /* SM9_ENC_SYS_ENABLE */
}

SM9_API int SM9_Alg_UEKG(const unsigned char *id, unsigned int ilen, unsigned char *ke, unsigned char *de)
{
#ifdef    SM9_ENC_SYS_ENABLE
    uint32_t                BN_t1[BNWordLen];
    uint32_t                BN_t2[BNWordLen];
    SM9_ECP2_A    Ecp2_ds;

    // Read System PriKey to BN
    SM9_Bn_ReadBytes(BN_t2, ke);

    // Compute t1 = H1(IDA||hid, N)+ks
    SM9_Hash_H1(BN_t1, id, ilen, SM9_HID_Enc, 1);
    bn_mod_add(BN_t1, BN_t1, BN_t2, sm9_sys_para.EC_N, sm9_sys_para.wsize);
    // Check t1 != 0
    if (bn_is_zero(BN_t1, sm9_sys_para.wsize))
        return SM9_ERR_ID_UNUSEABLE;
    // Compute t2 = ks*(t1^-1)
    BN_GetInv_Mont(BN_t1, BN_t1, sm9_sys_para.EC_N, sm9_sys_para.N_Mc, sm9_sys_para.N_R2, sm9_sys_para.wsize);
    bn_mont_mul(BN_t2, BN_t1, BN_t2, sm9_sys_para.EC_N, sm9_sys_para.N_Mc, sm9_sys_para.wsize);
    // Compute de = [t2]P1
    SM9_Ecp2_KP(&Ecp2_ds, &sm9_sys_para.EC_Fp2_G_Mont, BN_t2);

    // Convert User PriKey to bytes(in NormMode)
    SM9_Ecp2_A_WriteBytes(de, &Ecp2_ds);

    return SM9_OK;
#else
    return SM9_ERR_UNSUPPORT;
#endif /* SM9_ENC_SYS_ENABLE */
}

void SM9_Hash_KDF_Init(SM9_CTX *ctx, const unsigned char *C1, unsigned char *w, const unsigned char *id, unsigned int ilen)
{
    SM9_Hash_Init(&ctx->enc.xor_ctx);
    SM9_Hash_Update(&ctx->enc.xor_ctx, C1, 2 * BNByteLen);
    SM9_Hash_Update(&ctx->enc.xor_ctx, w, 12 * BNByteLen);
    SM9_Hash_Update(&ctx->enc.xor_ctx, id, ilen);
    ctx->enc.cnt[0] = ctx->enc.cnt[1] = ctx->enc.cnt[2] = 0;
    ctx->enc.cnt[3] = 1;
}

void SM9_Hash_KDF_Block(SM9_CTX *ctx, unsigned int cnt, unsigned char *k)
{
    SM9_Hash_Ctx tmp_ctx;
    unsigned char c[4];

    c[0] = (unsigned char)((cnt & 0xFF000000) >> 24);
    c[1] = (unsigned char)((cnt & 0x00FF0000) >> 16);
    c[2] = (unsigned char)((cnt & 0x0000FF00) >> 8);
    c[3] = (unsigned char)(cnt & 0x000000FF);
    memcpy(&tmp_ctx, &ctx->enc.xor_ctx, sizeof(SM9_Hash_Ctx));

    SM9_Hash_Update(&tmp_ctx, c, 4);
    SM9_Hash_Final(&tmp_ctx, k);
}

void _sm9_enc_init(SM9_CTX *ctx, const unsigned char *id, unsigned int ilen, unsigned char *r,
    const unsigned char *g, const unsigned char *mpk, unsigned char *C1)
{
    uint32_t BN_r[BNWordLen];
    uint32_t BN_h[BNWordLen];
    SM9_ECP_A Ecp_P;
    SM9_ECP_A Ecp_T;
    SM9_Fp12 Fp12_g;
    unsigned char pbW[12 * BNByteLen];

    // Read Random number r(in NormMode)
    SM9_Bn_ReadBytes(BN_r, r);
    // Read System PubKey to JPoint in MontMode
    SM9_Ecp_A_ReadBytes(&Ecp_P, mpk);

    // Get System Element g and convert to MontMode
    if (g)
    {//Read from input
        SM9_Fp12_ReadBytes(&Fp12_g, g);
        // w = g^r
        SM9_Fp12_Exp(&Fp12_g, &Fp12_g, BN_r);
    }
    else
    {//Compute by input
        SM9_Ecp_KP(&Ecp_T, &Ecp_P, BN_r);
        SM9_Alg_Pair_Mont(&Fp12_g, &Ecp_T, &sm9_sys_para.EC_Fp2_G_Mont);
    }
    SM9_Fp12_WriteBytes(pbW, &Fp12_g);

    // h1 = H1(IDB||hid, N)
    SM9_Hash_H1(BN_h, id, ilen, SM9_HID_Enc, 1);

    // QB=[h1]P1+Ppub-e
    SM9_Fp_ECP_KPAddAToA(&Ecp_P, &sm9_sys_para.EC_Fp_G_Mont, BN_h, &Ecp_P, &sm9_sys_para);

    // C1=[r]QB
    SM9_Ecp_KP(&Ecp_P, &Ecp_P, BN_r);
    SM9_Ecp_A_WriteBytes(C1, &Ecp_P);

    SM9_Hash_KDF_Init(ctx, C1, pbW, id, ilen);
    ctx->enc.bytes = 0;
}

// Key derivation function for public key encryption
// Mode-1: msg is not null, generate key stream and xor msg to enc
// Mode-2: msg is null and mlen is null, generate key stream with ctx's bytes record to enc
// Mode-3: msg is null and mlen is not null, generate key stream with mlen to enc
static void _sm9_pke_kdf(SM9_CTX *ctx, const unsigned char *msg, unsigned int mlen, unsigned char *enc)
{
    uint8_t    k[2*SM9_Hash_Size];
    unsigned int i, j;
    unsigned int cnt, res;

    cnt = ctx->enc.bytes / SM9_Hash_Size + 1;
    res = ctx->enc.bytes % SM9_Hash_Size;

    if (!msg)
    {
        if (mlen)
        {
            cnt = mlen / SM9_Hash_Size + 1;
            res = mlen % SM9_Hash_Size;
        }
        SM9_Hash_KDF_Block(ctx, cnt++, k);
        if (res)
        {
            SM9_Hash_KDF_Block(ctx, cnt++, k + SM9_Hash_Size);
        }
        memcpy(enc, k + res, SM9_Hash_Size);
        return;
    }

    if (res)
    {
        SM9_Hash_KDF_Block(ctx, cnt++, k);
        for (j = res; j < SM9_Hash_Size; j++)
            enc[j] = msg[j] ^ k[j];
        enc += SM9_Hash_Size - res;
        msg += SM9_Hash_Size - res;
        mlen -= SM9_Hash_Size - res;
        ctx->enc.bytes += SM9_Hash_Size - res;
    }

    for (i = 1; i <= mlen / SM9_Hash_Size; i++)
    {
        SM9_Hash_KDF_Block(ctx, cnt++, k);
        for (j = 0; j < SM9_Hash_Size; j++)
            enc[j] = msg[j] ^ k[j];
        enc += SM9_Hash_Size;
        msg += SM9_Hash_Size;
    }
    if ((res = mlen % SM9_Hash_Size) != 0)
    {
        SM9_Hash_KDF_Block(ctx, cnt++, k);
        for (j = 0; j < res; j++)
            enc[j] = msg[j] ^ k[j];
    }
    ctx->enc.bytes += mlen;
}

void SM9_Mac_Init(SM9_CTX *ctx)
{
    SM9_Hash_Init(&ctx->mac_ctx);
}

void SM9_Mac_Update(SM9_CTX *ctx, const unsigned char *msg, unsigned int mlen)
{
    SM9_Hash_Update(&ctx->mac_ctx, msg, mlen);
}

void SM9_Mac_Final(SM9_CTX *ctx, unsigned char *key, unsigned int klen, unsigned char *mac)
{
    SM9_Hash_Update(&ctx->mac_ctx, key, klen);
    SM9_Hash_Final(&ctx->mac_ctx, mac);
}

SM9_API int SM9_Alg_Enc(const unsigned char *msg, unsigned int mlen,
                const unsigned char *id,  unsigned int ilen, unsigned char *r,
                const unsigned char *g,   const unsigned char *mpk,
                unsigned char *enc, unsigned int *elen)
{
#ifdef    SM9_ENC_USR_ENABLE
    SM9_CTX    sm9_ctx;
    uint8_t    *C1, *C2, *C3;
    unsigned char mkey[SM9_Hash_Size];

#ifndef SM9_ALG_RND_ENABLE
    r = g_RandBuf;
    _ibc_alg_rand(r, BNByteLen);
#endif // SM9_ALG_RND_ENABLE

//#define SM9_ENC_ROUND_BEGIN        for(cnt = 0; cnt < 10000; cnt++)  {
//#define SM9_ENC_ROUND_END        }

#define SM9_ENC_ROUND_BEGIN
#define SM9_ENC_ROUND_END

    C1 = enc;
    C3 = C1 + SM9_C1_ByteLen;
    C2 = C3 + SM9_C3_ByteLen;

    if ((C2 > msg) && (C2 < msg + mlen))
        return SM9_ERR_BAD_INPUT;

    _sm9_enc_init(&sm9_ctx, id, ilen, r, g, mpk, C1);
    SM9_Mac_Init(&sm9_ctx);

    _sm9_pke_kdf(&sm9_ctx, msg, mlen, C2);
    SM9_Mac_Update(&sm9_ctx, C2, mlen);

    _sm9_pke_kdf(&sm9_ctx, 0, 0, mkey);
    SM9_Mac_Final(&sm9_ctx, mkey, SM9_Hash_Size, C3);

    if (elen)
        *elen = mlen + SM9_C1_ByteLen + SM9_C3_ByteLen;

    return SM9_OK;

#else
    return SM9_ERR_UNSUPPORT;
#endif /* SM9_ENC_USR_ENABLE */
}

int SM9_Dec_Init(SM9_CTX *ctx, const unsigned char *de, const unsigned char *id, unsigned int ilen, const unsigned char *C1)
{
    SM9_ECP_A    Ecp_P;
    SM9_ECP2_A    Ecp2_D;
    SM9_Fp12        Fp12_g;
    uint8_t                pbW[12 * BNByteLen];

    // Read User Prikey and convert to MontMode
    SM9_Ecp2_A_ReadBytes(&Ecp2_D, de);
    // Read Cipher Part1(in APoint MontMode)
    SM9_Ecp_A_ReadBytes(&Ecp_P, C1);

    // Check C1 is a point
    if (SM9_Ecp_A_Check(&Ecp_P))
        return SM9_ERR_INVALID_POINT;

    // w'=e(C1, de)
    SM9_Alg_Pair_Mont(&Fp12_g, &Ecp_P, &Ecp2_D);
    SM9_Fp12_WriteBytes(pbW, &Fp12_g);

    SM9_Hash_KDF_Init(ctx, C1, pbW, id, ilen);
    ctx->enc.bytes = 0;

    return SM9_OK;
}

SM9_API int SM9_Alg_Dec(const unsigned char *enc, unsigned int elen,
                const unsigned char *de, const unsigned char *id, unsigned int ilen,
                unsigned char *msg, unsigned int *mlen)
{
#ifdef    SM9_ENC_USR_ENABLE
    SM9_CTX    sm9_ctx;
    const uint8_t    *C1, *C2, *C3;
    uint8_t    k[2 * SM9_Hash_Size];
    uint8_t    mac[SM9_C3_ByteLen];
    unsigned int i, len;
    int ret;

    if (elen < SM9_C1_ByteLen + SM9_C3_ByteLen)
        return SM9_ERR_INPUT;
    len = elen - SM9_C1_ByteLen - SM9_C3_ByteLen;

    C1 = enc;
    C3 = C1 + SM9_C1_ByteLen;
    C2 = C3 + SM9_C3_ByteLen;

    ret = SM9_Dec_Init(&sm9_ctx, de, id, ilen, C1);
    if (ret != SM9_OK)
        return ret;
    SM9_Mac_Init(&sm9_ctx);

    SM9_Mac_Update(&sm9_ctx, C2, len);
    _sm9_pke_kdf(&sm9_ctx, 0, len, k);
    SM9_Mac_Final(&sm9_ctx, k, SM9_Hash_Size, mac);

    // Compute MAC(K2', C2) and Compare to C3
    for (i = 0; i < SM9_C3_ByteLen; i++)
    {
        if (mac[i] != C3[i])
            return SM9_ERR_MAC_FAILED;
    }

    _sm9_pke_kdf(&sm9_ctx, C2, len, msg);

    if (mlen)
        *mlen = elen - SM9_C1_ByteLen - SM9_C3_ByteLen;

    return SM9_OK;
#else
    return SM9_ERR_UNSUPPORT;
#endif /* SM9_ENC_USR_ENABLE */
}

/******************************************************************************/
/*                          SM9 Key Exchange                                  */
/******************************************************************************/

#ifdef SM9_KEYEX_ENABLE

// Key derivation function for key exchange
static void _sm9_keyex_kdf(uint8_t *Z, uint32_t Zlen, uint32_t klen, uint8_t *K)
{
    SM9_Hash_Ctx ctx;
    uint8_t ct[4];
    uint32_t cnt = 1;
    uint32_t rcnt = klen / SM9_Hash_Size;
    uint32_t rbit = klen % SM9_Hash_Size;
    uint32_t i;

    for (i = 0; i < rcnt; i++)
    {
        ct[0] = (unsigned char)((cnt & 0xFF000000) >> 24);
        ct[1] = (unsigned char)((cnt & 0x00FF0000) >> 16);
        ct[2] = (unsigned char)((cnt & 0x0000FF00) >> 8);
        ct[3] = (unsigned char)(cnt & 0x000000FF);

        SM9_Hash_Init(&ctx);
        SM9_Hash_Update(&ctx, Z, Zlen);
        SM9_Hash_Update(&ctx, ct, 4);
        SM9_Hash_Final(&ctx, K + i * SM9_Hash_Size);
        cnt++;
    }

    if (rbit)
    {
        uint8_t tmp[SM9_Hash_Size];
        ct[0] = (unsigned char)((cnt & 0xFF000000) >> 24);
        ct[1] = (unsigned char)((cnt & 0x00FF0000) >> 16);
        ct[2] = (unsigned char)((cnt & 0x0000FF00) >> 8);
        ct[3] = (unsigned char)(cnt & 0x000000FF);

        SM9_Hash_Init(&ctx);
        SM9_Hash_Update(&ctx, Z, Zlen);
        SM9_Hash_Update(&ctx, ct, 4);
        SM9_Hash_Final(&ctx, tmp);
        memcpy(K + rcnt * SM9_Hash_Size, tmp, rbit);
    }
}

// Compute hash for key exchange confirmation
__attribute__((unused)) static void _sm9_keyex_hash(uint8_t tag, uint8_t *Z, uint32_t Zlen, uint8_t *hash)
{
    SM9_Hash_Ctx ctx;
    uint8_t Ztag[1];

    Ztag[0] = tag;
    SM9_Hash_Init(&ctx);
    SM9_Hash_Update(&ctx, Ztag, 1);
    SM9_Hash_Update(&ctx, Z, Zlen);
    SM9_Hash_Final(&ctx, hash);
}

SM9_API int SM9_Alg_KeyEx_InitA(
    unsigned char *ida,
    unsigned int  ilen_a,
    unsigned char *idb,
    unsigned int  ilen_b,
    unsigned char *ra,
    unsigned char *da,
    unsigned char *mpk,
    unsigned char *RA)
{
#ifdef SM9_KEYEX_ENABLE
    uint32_t BN_ra[BNWordLen];
    SM9_ECP_A Ecp_QB;
    SM9_ECP_A Ecp_RA;
    uint32_t BN_h1[BNWordLen];

    (void)ida;
    (void)ilen_a;
    (void)da;

    // Read random number ra
    SM9_Bn_ReadBytes(BN_ra, ra);
    SM9_Fn_LastRes(BN_ra);
    if (SM9_Bn_IsZero(BN_ra))
        return SM9_ERR_RND_UNUSEABLE;

    // Read system public key (for encryption system, mpk is on G1)
    SM9_Ecp_A_ReadBytes(&Ecp_QB, mpk);

    // Compute h1 = H1(IDB||hid, N) - Note: use IDB for QB! Must use same HID as key generation
    SM9_Hash_H1(BN_h1, idb, ilen_b, SM9_HID_Enc, 1);

    // Compute QB = [h1]P1 + Ppub
    SM9_Fp_ECP_KPAddAToA(&Ecp_QB, &sm9_sys_para.EC_Fp_G_Mont, BN_h1, &Ecp_QB, &sm9_sys_para);

    // Compute RA = [ra]QB
    SM9_Ecp_KP(&Ecp_RA, &Ecp_QB, BN_ra);

    // Output RA
    SM9_Ecp_A_WriteBytes(RA, &Ecp_RA);

    return SM9_OK;
#else
    return SM9_ERR_UNSUPPORT;
#endif
}

SM9_API int SM9_Alg_KeyEx_InitB(
    unsigned char *ida,
    unsigned int  ilen_a,
    unsigned char *idb,
    unsigned int  ilen_b,
    unsigned char *rb,
    unsigned char *db,
    unsigned char *mpk,
    unsigned char *RB)
{
#ifdef SM9_KEYEX_ENABLE
    uint32_t BN_rb[BNWordLen];
    SM9_ECP_A Ecp_QA;
    SM9_ECP_A Ecp_RB;
    uint32_t BN_h1[BNWordLen];

    (void)idb;
    (void)ilen_b;
    (void)db;

    // Read random number rb
    SM9_Bn_ReadBytes(BN_rb, rb);
    SM9_Fn_LastRes(BN_rb);
    if (SM9_Bn_IsZero(BN_rb))
        return SM9_ERR_RND_UNUSEABLE;

    // Read system public key (for encryption system, mpk is on G1)
    SM9_Ecp_A_ReadBytes(&Ecp_QA, mpk);

    // Compute h1 = H1(IDA||hid, N) - Note: use IDA for QA! Must use same HID as key generation
    SM9_Hash_H1(BN_h1, ida, ilen_a, SM9_HID_Enc, 1);

    // Compute QA = [h1]P1 + Ppub
    SM9_Fp_ECP_KPAddAToA(&Ecp_QA, &sm9_sys_para.EC_Fp_G_Mont, BN_h1, &Ecp_QA, &sm9_sys_para);

    // Compute RB = [rb]QA
    SM9_Ecp_KP(&Ecp_RB, &Ecp_QA, BN_rb);

    // Output RB
    SM9_Ecp_A_WriteBytes(RB, &Ecp_RB);

    return SM9_OK;
#else
    return SM9_ERR_UNSUPPORT;
#endif
}

SM9_API int SM9_Alg_KeyEx_ConfirmA(
    unsigned char *ida,
    unsigned int  ilen_a,
    unsigned char *idb,
    unsigned int  ilen_b,
    unsigned char *ra,
    unsigned char *RA,
    unsigned char *RB,
    unsigned char *da,
    unsigned char *mpk,
    unsigned int  klen,
    unsigned char *SK,
    unsigned char *SA)
{
#ifdef SM9_KEYEX_ENABLE
    uint32_t BN_ra[BNWordLen];
    SM9_ECP2_A Ecp2_dA;
    SM9_ECP_A Ecp_RB;
    SM9_Fp12 Fp12_g1, Fp12_g2, Fp12_g3;
    uint8_t g1_bytes[12 * BNByteLen];
    uint8_t g2_bytes[12 * BNByteLen];
    uint8_t g3_bytes[12 * BNByteLen];
    uint8_t Z[2048];
    uint32_t Zlen = 0;
    uint8_t inner_hash[SM9_Hash_Size];
    SM9_Hash_Ctx ctx;

    // Read random number ra
    SM9_Bn_ReadBytes(BN_ra, ra);

    // Read user private key dA (for encryption system, it's on G2)
    SM9_Ecp2_A_ReadBytes(&Ecp2_dA, da);

    // Read RB (G1 point)
    SM9_Ecp_A_ReadBytes(&Ecp_RB, RB);

    // User A computes (according to the diagram):
    // g1 = e(Ppub, P2)^rA
    SM9_ECP_A Ecp_Ppub;
    SM9_Ecp_A_ReadBytes(&Ecp_Ppub, mpk);
    SM9_Alg_Pair_Mont(&Fp12_g1, &Ecp_Ppub, &sm9_sys_para.EC_Fp2_G_Mont);
    SM9_Fp12_Exp(&Fp12_g1, &Fp12_g1, BN_ra);

    // g2 = e(RB, dA)
    SM9_Alg_Pair_Mont(&Fp12_g2, &Ecp_RB, &Ecp2_dA);

    // g3 = g2^rA
    SM9_Fp12_Exp(&Fp12_g3, &Fp12_g2, BN_ra);

    // Convert to bytes
    SM9_Fp12_WriteBytes(g1_bytes, &Fp12_g1);
    SM9_Fp12_WriteBytes(g2_bytes, &Fp12_g2);
    SM9_Fp12_WriteBytes(g3_bytes, &Fp12_g3);

    // Compute inner_hash = Hash(g2 || g3 || IDA || IDB || RA || RB)
    SM9_Hash_Init(&ctx);
    SM9_Hash_Update(&ctx, g2_bytes, 12 * BNByteLen);
    SM9_Hash_Update(&ctx, g3_bytes, 12 * BNByteLen);
    SM9_Hash_Update(&ctx, ida, ilen_a);
    SM9_Hash_Update(&ctx, idb, ilen_b);
    SM9_Hash_Update(&ctx, RA, 2 * BNByteLen);
    SM9_Hash_Update(&ctx, RB, 2 * BNByteLen);
    SM9_Hash_Final(&ctx, inner_hash);

    // Compute Z = g1 || Hash(g2||g3||IDA||IDB||RA||RB)  (according to diagram note: X=g1||Hash(g2||g3||IDA||IDB||RA||RB))
    memcpy(Z + Zlen, g1_bytes, 12 * BNByteLen);
    Zlen += 12 * BNByteLen;
    memcpy(Z + Zlen, inner_hash, SM9_Hash_Size);
    Zlen += SM9_Hash_Size;

    // Derive shared key: SK = KDF(IDA||IDB||RA||RB||g1||g2||g3, klen)
    _sm9_keyex_kdf(Z, Zlen, klen, SK);

    // Compute SA = Hash(0x82 || g1 || Hash(g2||g3||IDA||IDB||RA||RB))
    if (SA)
    {
        uint8_t temp[1 + 12 * BNByteLen + SM9_Hash_Size];
        temp[0] = 0x82;
        memcpy(temp + 1, g1_bytes, 12 * BNByteLen);
        memcpy(temp + 1 + 12 * BNByteLen, inner_hash, SM9_Hash_Size);

        SM9_Hash_Init(&ctx);
        SM9_Hash_Update(&ctx, temp, 1 + 12 * BNByteLen + SM9_Hash_Size);
        SM9_Hash_Final(&ctx, SA);
    }

    return SM9_OK;
#else
    return SM9_ERR_UNSUPPORT;
#endif
}

SM9_API int SM9_Alg_KeyEx_ConfirmB(
    unsigned char *ida,
    unsigned int  ilen_a,
    unsigned char *idb,
    unsigned int  ilen_b,
    unsigned char *rb,
    unsigned char *RA,
    unsigned char *RB,
    unsigned char *db,
    unsigned char *mpk,
    unsigned int  klen,
    unsigned char *SK,
    unsigned char *SB)
{
#ifdef SM9_KEYEX_ENABLE
    uint32_t BN_rb[BNWordLen];
    SM9_ECP2_A Ecp2_dB;
    SM9_ECP_A Ecp_RA;
    SM9_Fp12 Fp12_g1, Fp12_g2, Fp12_g3;
    uint8_t g1_bytes[12 * BNByteLen];
    uint8_t g2_bytes[12 * BNByteLen];
    uint8_t g3_bytes[12 * BNByteLen];
    uint8_t Z[2048];
    uint32_t Zlen = 0;
    uint8_t inner_hash[SM9_Hash_Size];
    SM9_Hash_Ctx ctx;

    // Read random number rb
    SM9_Bn_ReadBytes(BN_rb, rb);

    // Read user private key dB (for encryption system, it's on G2)
    SM9_Ecp2_A_ReadBytes(&Ecp2_dB, db);

    // Read RA (G1 point)
    SM9_Ecp_A_ReadBytes(&Ecp_RA, RA);

    // User B computes (according to the diagram):
    // g1 = e(RA, dB)
    SM9_Alg_Pair_Mont(&Fp12_g1, &Ecp_RA, &Ecp2_dB);

    // g2 = e(Ppub, P2)^rB
    SM9_ECP_A Ecp_Ppub;
    SM9_Ecp_A_ReadBytes(&Ecp_Ppub, mpk);
    SM9_Alg_Pair_Mont(&Fp12_g2, &Ecp_Ppub, &sm9_sys_para.EC_Fp2_G_Mont);
    SM9_Fp12_Exp(&Fp12_g2, &Fp12_g2, BN_rb);

    // g3 = g1^rB
    SM9_Fp12_Exp(&Fp12_g3, &Fp12_g1, BN_rb);

    // Convert to bytes
    SM9_Fp12_WriteBytes(g1_bytes, &Fp12_g1);
    SM9_Fp12_WriteBytes(g2_bytes, &Fp12_g2);
    SM9_Fp12_WriteBytes(g3_bytes, &Fp12_g3);

    // Compute inner_hash = Hash(g2 || g3 || IDA || IDB || RA || RB)
    SM9_Hash_Init(&ctx);
    SM9_Hash_Update(&ctx, g2_bytes, 12 * BNByteLen);
    SM9_Hash_Update(&ctx, g3_bytes, 12 * BNByteLen);
    SM9_Hash_Update(&ctx, ida, ilen_a);
    SM9_Hash_Update(&ctx, idb, ilen_b);
    SM9_Hash_Update(&ctx, RA, 2 * BNByteLen);
    SM9_Hash_Update(&ctx, RB, 2 * BNByteLen);
    SM9_Hash_Final(&ctx, inner_hash);

    // Compute Z = g1 || Hash(g2||g3||IDA||IDB||RA||RB)
    memcpy(Z + Zlen, g1_bytes, 12 * BNByteLen);
    Zlen += 12 * BNByteLen;
    memcpy(Z + Zlen, inner_hash, SM9_Hash_Size);
    Zlen += SM9_Hash_Size;

    // Derive shared key: SK = KDF(Z, klen)
    _sm9_keyex_kdf(Z, Zlen, klen, SK);

    // Compute SB = Hash(0x83 || g1 || Hash(g2||g3||IDA||IDB||RA||RB))
    if (SB)
    {
        uint8_t temp[1 + 12 * BNByteLen + SM9_Hash_Size];

        temp[0] = 0x83;
        memcpy(temp + 1, g1_bytes, 12 * BNByteLen);
        memcpy(temp + 1 + 12 * BNByteLen, inner_hash, SM9_Hash_Size);

        SM9_Hash_Init(&ctx);
        SM9_Hash_Update(&ctx, temp, 1 + 12 * BNByteLen + SM9_Hash_Size);
        SM9_Hash_Final(&ctx, SB);
    }

    return SM9_OK;
#else
    return SM9_ERR_UNSUPPORT;
#endif
}

// Verify SA received from User A (for User B to verify A's confirmation)
SM9_API int SM9_Alg_KeyEx_VerifySA(
    unsigned char *ida,
    unsigned int  ilen_a,
    unsigned char *idb,
    unsigned int  ilen_b,
    unsigned char *rb,
    unsigned char *RA,
    unsigned char *RB,
    unsigned char *db,
    unsigned char *mpk,
    unsigned char *SA)
{
#ifdef SM9_KEYEX_ENABLE
    uint32_t BN_rb[BNWordLen];
    SM9_ECP2_A Ecp2_dB;
    SM9_ECP_A Ecp_RA;
    SM9_Fp12 Fp12_g1, Fp12_g2, Fp12_g3;
    uint8_t g1_bytes[12 * BNByteLen];
    uint8_t g2_bytes[12 * BNByteLen];
    uint8_t g3_bytes[12 * BNByteLen];
    uint8_t inner_hash[SM9_Hash_Size];
    uint8_t expected_sa[SM9_Hash_Size];
    SM9_Hash_Ctx ctx;
    uint32_t i;

    // Read random number rb
    SM9_Bn_ReadBytes(BN_rb, rb);

    // Read user private key dB (for encryption system, it's on G2)
    SM9_Ecp2_A_ReadBytes(&Ecp2_dB, db);

    // Read RA (G1 point)
    SM9_Ecp_A_ReadBytes(&Ecp_RA, RA);

    // User B computes (same as in ConfirmB):
    // g1 = e(RA, dB)
    SM9_Alg_Pair_Mont(&Fp12_g1, &Ecp_RA, &Ecp2_dB);

    // g2 = e(Ppub, P2)^rB
    SM9_ECP_A Ecp_Ppub;
    SM9_Ecp_A_ReadBytes(&Ecp_Ppub, mpk);
    SM9_Alg_Pair_Mont(&Fp12_g2, &Ecp_Ppub, &sm9_sys_para.EC_Fp2_G_Mont);
    SM9_Fp12_Exp(&Fp12_g2, &Fp12_g2, BN_rb);

    // g3 = g1^rB
    SM9_Fp12_Exp(&Fp12_g3, &Fp12_g1, BN_rb);

    // Convert to bytes
    SM9_Fp12_WriteBytes(g1_bytes, &Fp12_g1);
    SM9_Fp12_WriteBytes(g2_bytes, &Fp12_g2);
    SM9_Fp12_WriteBytes(g3_bytes, &Fp12_g3);

    // Compute inner_hash = Hash(g2 || g3 || IDA || IDB || RA || RB)
    SM9_Hash_Init(&ctx);
    SM9_Hash_Update(&ctx, g2_bytes, 12 * BNByteLen);
    SM9_Hash_Update(&ctx, g3_bytes, 12 * BNByteLen);
    SM9_Hash_Update(&ctx, ida, ilen_a);
    SM9_Hash_Update(&ctx, idb, ilen_b);
    SM9_Hash_Update(&ctx, RA, 2 * BNByteLen);
    SM9_Hash_Update(&ctx, RB, 2 * BNByteLen);
    SM9_Hash_Final(&ctx, inner_hash);

    // Compute expected SA = Hash(0x82 || g1 || Hash(g2||g3||IDA||IDB||RA||RB))
    {
        uint8_t temp[1 + 12 * BNByteLen + SM9_Hash_Size];

        temp[0] = 0x82;
        memcpy(temp + 1, g1_bytes, 12 * BNByteLen);
        memcpy(temp + 1 + 12 * BNByteLen, inner_hash, SM9_Hash_Size);

        SM9_Hash_Init(&ctx);
        SM9_Hash_Update(&ctx, temp, 1 + 12 * BNByteLen + SM9_Hash_Size);
        SM9_Hash_Final(&ctx, expected_sa);
    }

    // Verify SA
    for (i = 0; i < SM9_Hash_Size; i++)
    {
        if (SA[i] != expected_sa[i])
            return SM9_ERR_VERIFY_FAILED;
    }

    return SM9_OK;
#else
    return SM9_ERR_UNSUPPORT;
#endif
}

// Verify SB received from User B (for User A to verify B's confirmation)
SM9_API int SM9_Alg_KeyEx_VerifySB(
    unsigned char *ida,
    unsigned int  ilen_a,
    unsigned char *idb,
    unsigned int  ilen_b,
    unsigned char *ra,
    unsigned char *RA,
    unsigned char *RB,
    unsigned char *da,
    unsigned char *mpk,
    unsigned char *SB)
{
#ifdef SM9_KEYEX_ENABLE
    uint32_t BN_ra[BNWordLen];
    SM9_ECP2_A Ecp2_dA;
    SM9_ECP_A Ecp_RB;
    SM9_Fp12 Fp12_g1, Fp12_g2, Fp12_g3;
    uint8_t g1_bytes[12 * BNByteLen];
    uint8_t g2_bytes[12 * BNByteLen];
    uint8_t g3_bytes[12 * BNByteLen];
    uint8_t inner_hash[SM9_Hash_Size];
    uint8_t expected_sb[SM9_Hash_Size];
    SM9_Hash_Ctx ctx;
    uint32_t i;

    // Read random number ra
    SM9_Bn_ReadBytes(BN_ra, ra);

    // Read user private key dA (for encryption system, it's on G2)
    SM9_Ecp2_A_ReadBytes(&Ecp2_dA, da);

    // Read RB (G1 point)
    SM9_Ecp_A_ReadBytes(&Ecp_RB, RB);

    // User A computes (same as in ConfirmA):
    // g1 = e(Ppub, P2)^rA
    SM9_ECP_A Ecp_Ppub;
    SM9_Ecp_A_ReadBytes(&Ecp_Ppub, mpk);
    SM9_Alg_Pair_Mont(&Fp12_g1, &Ecp_Ppub, &sm9_sys_para.EC_Fp2_G_Mont);
    SM9_Fp12_Exp(&Fp12_g1, &Fp12_g1, BN_ra);

    // g2 = e(RB, dA)
    SM9_Alg_Pair_Mont(&Fp12_g2, &Ecp_RB, &Ecp2_dA);

    // g3 = g2^rA
    SM9_Fp12_Exp(&Fp12_g3, &Fp12_g2, BN_ra);

    // Convert to bytes
    SM9_Fp12_WriteBytes(g1_bytes, &Fp12_g1);
    SM9_Fp12_WriteBytes(g2_bytes, &Fp12_g2);
    SM9_Fp12_WriteBytes(g3_bytes, &Fp12_g3);

    // Compute inner_hash = Hash(g2 || g3 || IDA || IDB || RA || RB)
    SM9_Hash_Init(&ctx);
    SM9_Hash_Update(&ctx, g2_bytes, 12 * BNByteLen);
    SM9_Hash_Update(&ctx, g3_bytes, 12 * BNByteLen);
    SM9_Hash_Update(&ctx, ida, ilen_a);
    SM9_Hash_Update(&ctx, idb, ilen_b);
    SM9_Hash_Update(&ctx, RA, 2 * BNByteLen);
    SM9_Hash_Update(&ctx, RB, 2 * BNByteLen);
    SM9_Hash_Final(&ctx, inner_hash);

    // Compute expected SB = Hash(0x83 || g1 || Hash(g2||g3||IDA||IDB||RA||RB))
    {
        uint8_t temp[1 + 12 * BNByteLen + SM9_Hash_Size];

        temp[0] = 0x83;
        memcpy(temp + 1, g1_bytes, 12 * BNByteLen);
        memcpy(temp + 1 + 12 * BNByteLen, inner_hash, SM9_Hash_Size);

        SM9_Hash_Init(&ctx);
        SM9_Hash_Update(&ctx, temp, 1 + 12 * BNByteLen + SM9_Hash_Size);
        SM9_Hash_Final(&ctx, expected_sb);
    }

    // Verify SB
    for (i = 0; i < SM9_Hash_Size; i++)
    {
        if (SB[i] != expected_sb[i])
            return SM9_ERR_VERIFY_FAILED;
    }

    return SM9_OK;
#else
    return SM9_ERR_UNSUPPORT;
#endif
}

#endif // HITLS_CRYPTO_SM9

#endif /* SM9_KEYEX_ENABLE */
