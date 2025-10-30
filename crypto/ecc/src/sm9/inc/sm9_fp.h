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

#ifndef _SM9_FP_H_
#define _SM9_FP_H_

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM9

#include "bn.h"
#include "sm9_curve.h"
#include <memory.h>

// Field P
#define SM9_Fp_Assign(Fpz, Fp_x)        \
    if ((Fpz) != (Fp_x))    \
        {memcpy(Fpz, Fp_x, 4 * sm9_sys_para.wsize); }
#define SM9_Fp_SetOne(Fpz)        \
    memcpy(Fpz, sm9_sys_para.Q_R1, 4 * sm9_sys_para.wsize)
#define SM9_Fq_IsZero(Fpx)        \
    bn_is_zero(Fpx, sm9_sys_para.wsize)

#define SM9_Fp_Add(Fp_z, Fp_x, Fp_y)    \
    bn_mod_add(Fp_z, Fp_x, Fp_y, sm9_sys_para.EC_Q, sm9_sys_para.wsize)

#define SM9_Fp_Sub(Fp_z, Fp_x, Fp_y)    \
    bn_mod_sub(Fp_z, Fp_x, Fp_y, sm9_sys_para.EC_Q, sm9_sys_para.wsize)

#define SM9_Fp_Neg(Fp_z, Fp_x)    \
    bn_mod_sub(Fp_z, sm9_sys_para.EC_Q, Fp_x, sm9_sys_para.EC_Q, sm9_sys_para.wsize)

#define SM9_Fp_LastRes(Fp_x)    \
    bn_get_res(Fp_x, sm9_sys_para.EC_Q, sm9_sys_para.wsize)

#define SM9_Fp_Mul(Fp_z, Fp_x, Fp_y)    \
    bn_mont_mul(Fp_z, Fp_x, Fp_y, sm9_sys_para.EC_Q, sm9_sys_para.Q_Mc, sm9_sys_para.wsize)

#define SM9_Fp_Squ(Fp_z, Fp_x)    \
    bn_mont_mul(Fp_z, Fp_x, Fp_x, sm9_sys_para.EC_Q, sm9_sys_para.Q_Mc, sm9_sys_para.wsize)

#define SM9_Fp_Inv(Fp_z, Fp_x)    \
    bn_mont_mul(Fp_z, Fp_x, sm9_sys_para.EC_One, sm9_sys_para.EC_Q, sm9_sys_para.Q_Mc, sm9_sys_para.wsize); \
    BN_GetInv_Mont(Fp_z, Fp_z, sm9_sys_para.EC_Q, sm9_sys_para.Q_Mc, sm9_sys_para.Q_R2, sm9_sys_para.wsize);

#define SM9_Fp_MulRoot(Fp_z, Fp_x)    \
    bn_mont_mul(Fp_z, Fp_x, sm9_sys_para.EC_Root_Mont, sm9_sys_para.EC_Q, sm9_sys_para.Q_Mc, sm9_sys_para.wsize);

// Field N
#define SM9_Bn_ReadBytes(x, src)    \
    ByteToBN(src, BNByteLen, x, BNWordLen)

#define SM9_Bn_IsZero(x)    \
    bn_is_zero(x, sm9_sys_para.wsize)

#define SM9_Fn_LastRes(Fp_x)    \
    bn_get_res(Fp_x, sm9_sys_para.EC_N, sm9_sys_para.wsize)

#define SM9_Fn_Sub(Fn_z, Fn_x, Fn_y)    \
    bn_mod_sub(Fn_z, Fn_x, Fn_y, sm9_sys_para.EC_N, sm9_sys_para.wsize)

#define SM9_Fn_Add(Fn_z, Fn_x, Fn_y)    \
    bn_mod_add(Fn_z, Fn_x, Fn_y, sm9_sys_para.EC_N, sm9_sys_para.wsize)

#ifdef  __cplusplus
extern "C" {
#endif

void SM9_Fp_ReadBytes(uint32_t *dst, const unsigned char *src);

void SM9_Fp_WriteBytes(unsigned char *dst, uint32_t *src);

#ifdef  __cplusplus
}
#endif

#endif // HITLS_CRYPTO_SM9

#endif // !_SM9_FP_H_
