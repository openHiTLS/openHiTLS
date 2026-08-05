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

#ifndef SLH_DSA_HASH_H
#define SLH_DSA_HASH_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SLH_DSA

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * 根据 SLH-DSA 哈希族解析配套的哈希函数表和地址操作集。
 * SHA2 参数集使用压缩地址，SHAKE 参数集使用完整地址。
 *
 * @param hashFamily [IN]  哈希族。
 * @param hashFuncs  [OUT] 哈希函数表，调用方必须保证指针非空。
 * @param adrsOps    [OUT] 地址操作集，调用方必须保证指针非空。
 * @retval CRYPT_SUCCESS 解析成功。
 * @retval CRYPT_INVALID_ARG 不支持的哈希族。
 */
int32_t SlhDsaResolveMathMethods(SlhDsaHashFamily hashFamily, const HbsHashFuncs **hashFuncs, HbsAdrsOps *adrsOps);

/*
 * SLH-DSA-SHA2: PreHash pkseed and padding then save the mdctx
 * @param ctx       SLH-DSA context
 * @param pubSeed   public seed used to initialize the md ctx
 */
int32_t InitMdCtx(CryptSlhDsaCtx *ctx, const uint8_t *pubSeed);

/*
 * SLH-DSA-SHA2: dup the md ctx
 * @param dest  dest SLH-DSA context
 * @param src   source SLH-DSA context
 */
void DupMdCtx(CryptSlhDsaCtx *dest, CryptSlhDsaCtx *src);

/*
 * SLH-DSA-SHA2: free the md ctx
 * @param ctx   SLH-DSA context
 */
void FreeMdCtx(CryptSlhDsaCtx *ctx);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HITLS_CRYPTO_SLH_DSA */
#endif /* SLH_DSA_HASH_H */
