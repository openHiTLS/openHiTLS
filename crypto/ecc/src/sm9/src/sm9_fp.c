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

#include "sm9_fp.h"
#include "bn.h"

void SM9_Fp_ReadBytes(uint32_t *dst, const unsigned char *src)
{
    ByteToBN(src, BNByteLen, dst, BNWordLen);
    bn_mont_mul(dst, dst, sm9_sys_para.Q_R2, sm9_sys_para.EC_Q, sm9_sys_para.Q_Mc, sm9_sys_para.wsize);
}

void SM9_Fp_WriteBytes(unsigned char *dst, uint32_t *src)
{
    uint32_t tmp[BNWordLen];

    bn_mont_mul(tmp, src, sm9_sys_para.EC_One, sm9_sys_para.EC_Q, sm9_sys_para.Q_Mc, sm9_sys_para.wsize);
    bn_get_res(tmp, sm9_sys_para.EC_Q, sm9_sys_para.wsize);
    BNToByte(tmp, BNWordLen, dst, 0);
}

#endif // HITLS_CRYPTO_SM9
