/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
/* INCLUDE_BASE test_suite_sdv_eal_rsa */

/* BEGIN_HEADER */

#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

#include "bsl_errno.h"
#include "crypt_eal_md.h"
#include "crypt_eal_pkey.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include "crypt_bn.h"
#include "bsl_sal.h"
#include "crypt_algid.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "stub_replace.h"
#include "crypt_eal_rand.h"
#include "crypt_util_rand.h"
#include "eal_pkey_local.h"
#include "crypt_rsa.h"
#include "rsa_local.h"
#include "bn_basic.h"
#include "securec.h"

/* END_HEADER */

#define CRYPT_EAL_PKEY_KEYMGMT_OPERATE 0
#define CRYPT_EAL_PKEY_CIPHER_OPERATE  1
#define CRYPT_EAL_PKEY_EXCH_OPERATE    2
#define CRYPT_EAL_PKEY_SIGN_OPERATE    4

/**
 * @test   SDV_CRYPTO_RSA_CRYPT_PROVIDER_FUNC_TC001
 * @title  RSA EAL abnormal test: The encryption and decryption padding modes do not match for the default provider.
 * @precon Vectors: a rsa key pair, plaintext
 * @brief
 *    1. Create the context(pkey) of the rsa algorithm using default provider, expected result 1
 *    2. Initialize the DRBG.
 *    3. Set public key, and set padding mode to OAEP, expected result 2
 *    4. Call the CRYPT_EAL_PkeyEncrypt to encrypt plaintext, expected result 3
 *    5. Set private key, and set padding mode to PKCSV15, expected result 4
 *    6. Call the CRYPT_EAL_PkeyDecrypt to decrypt the output of step 4, expected result 5
 *    7. Set private key, and set padding mode to OAEP, expected result 6
 *    8. Call the CRYPT_EAL_PkeyDecrypt to decrypt the output of step 4, expected result 7
 *    9. Compare the output data of step 8 with plaintext, expected result 8
 * @expect
 *    1. Success, and context is not NULL.
 *    2-4. CRYPT_SUCCESS
 *    5. CRYPT_RSA_NOR_VERIFY_FAIL
 *    6-7. CRYPT_SUCCESS
 *    8. Both are the same.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_CRYPT_PROVIDER_FUNC_TC001(Hex *n, Hex *e, Hex *d, Hex *plaintext)
{
    TestMemInit();
    uint8_t ct[MAX_CIPHERTEXT_LEN] = {0};
    uint8_t pt[MAX_CIPHERTEXT_LEN] = {0};
    uint32_t msgLen = MAX_CIPHERTEXT_LEN;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPrv prvkey = {0};
    CRYPT_EAL_PkeyPub pubkey = {0};
    CRYPT_RSA_OaepPara oaepPara = {.mdId = CRYPT_MD_SHA1, .mgfId = CRYPT_MD_SHA1};
    CRYPT_RSA_PkcsV15Para pkcsv15 = {CRYPT_MD_SHA1};

    SetRsaPrvKey(&prvkey, n->x, n->len, d->x, d->len);
    SetRsaPubKey(&pubkey, n->x, n->len, e->x, e->len);
    pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE+CRYPT_EAL_PKEY_CIPHER_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);

    CRYPT_RandRegist(RandFunc);

    /* HiTLS public key encrypt: OAEP */
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(pkey, &pubkey) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_RSAES_OAEP, &oaepPara, OAEP_SIZE) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyEncrypt(pkey, plaintext->x, plaintext->len, ct, &msgLen) == CRYPT_SUCCESS);

    /* HiTLS private key encrypt: PKCSV15 */
    ASSERT_TRUE(CRYPT_EAL_PkeySetPrv(pkey, &prvkey) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_RSAES_PKCSV15, &pkcsv15, PKCSV15_SIZE) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, ct, msgLen, pt, &msgLen) == CRYPT_RSA_NOR_VERIFY_FAIL);

    /* HiTLS private key encrypt: OAEP */
    ASSERT_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_RSAES_OAEP, &oaepPara, OAEP_SIZE) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyDecrypt(pkey, ct, msgLen, pt, &msgLen) == CRYPT_SUCCESS);
    ASSERT_TRUE(msgLen == plaintext->len);
    ASSERT_TRUE(memcmp(pt, plaintext->x, msgLen) == 0);

exit:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */


/**
 * @test   SDV_CRYPTO_RSA_GEN_SIGN_VERIFY_PKCSV15_PROVIDER_FUNC_TC001
 * @title  RSA EAL sign/verify and signData/verifyData:PKCSV15, sha256 for the default provider.
 * @precon
 * @brief
 *    Load the default provider and use the test vector to test its correctness
 *    1. Create the context(pkeyCtx) of the rsa algorithm using the default provider, expected result 1
 *    2. Call the CRYPT_EAL_PkeySetPara, where bits are: 1024/2048/4096, expected result 2
 *    3. Initialize the DRBG, expected result 3
 *    4. Call the CRYPT_EAL_PkeyGen to generate a key pair, expected result 4
 *    5. Call the CRYPT_EAL_PkeyGen to generate a key pair again, expected result 5
 *    6. Set padding type to pkcsv15, expected result 6
 *    7. Call the CRYPT_EAL_PkeySign method and use pkey to sign a piece of data, expected result 7
 *    8. Call the CRYPT_EAL_PkeyVerify method and use pkey to verify the signed data, expected result 8
 *    9. Call the CRYPT_EAL_PkeySignData method and use pkey to sign a piece of hash data, expected result 9
 *    10. Call the CRYPT_EAL_PkeyVerifyData method and use pkey to verify the signed data, expected result 10
 *    11. Allocate the memory for the CRYPT_EAL_PkeyCtx, named cpyCtx, expected result 11
 *    12. Call the CRYPT_EAL_PkeyCopyCtx to copy pkeyCtx, expected result 12
 *    13. Call the CRYPT_EAL_PkeySignData method and use cpyCtx to sign a piece of data, expected result 13
 *    14. Call the CRYPT_EAL_PkeyVerifyData method and use cpyCtx to verify the signed data, expected result 14
 * @expect
 *    1. Success, and context is not NULL.
 *    2-10. CRYPT_SUCCESS
 *    11. Success.
 *    12-14. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_GEN_SIGN_VERIFY_PKCSV15_PROVIDER_FUNC_TC001(int bits)
{
#ifndef HITLS_CRYPTO_SHA256
    SKIP_TEST();
#endif
    uint32_t signLen = (bits + 7) >> 3;  // keybytes == (keyBits + 7) >> 3 */
    int mdId = CRYPT_MD_SHA256;
    uint8_t data[500] = {0};
    const uint32_t dataLen = sizeof(data);
    uint8_t hash[32];  // SHA256 digest length: 32
    const uint32_t hashLen = sizeof(hash);
    uint8_t e[] = {1, 0, 1};

    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE+CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    CRYPT_EAL_PkeyCtx *cpyCtx = NULL;
    CRYPT_RSA_PkcsV15Para pkcsv15 = {mdId};
    CRYPT_EAL_PkeyPara para = {0};

    SetRsaPara(&para, e, 3, bits);

    uint8_t *sign = malloc(signLen);
    ASSERT_TRUE_AND_LOG("Malloc Sign Buffer", sign != NULL);

    TestMemInit();
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, PKCSV15_SIZE), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, mdId, data, dataLen, sign, &signLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, mdId, data, dataLen, sign, signLen), CRYPT_SUCCESS);

    signLen = (bits + 7) >> 3;  // keybytes == (keyBits + 7) >> 3 */
    memset_s(hash, sizeof(hash), 'A', sizeof(hash));
    ASSERT_EQ(CRYPT_EAL_PkeySignData(pkey, hash, hashLen, sign, &signLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyVerifyData(pkey, hash, hashLen, sign, signLen), CRYPT_SUCCESS);

    cpyCtx = BSL_SAL_Calloc(1u, sizeof(CRYPT_EAL_PkeyCtx));
    ASSERT_TRUE(cpyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCopyCtx(cpyCtx, pkey), CRYPT_SUCCESS);

    signLen = (bits + 7) >> 3;
    ASSERT_EQ(CRYPT_EAL_PkeySign(cpyCtx, mdId, data, dataLen, sign, &signLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(cpyCtx, mdId, data, dataLen, sign, signLen), CRYPT_SUCCESS);

exit:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(cpyCtx);
    free(sign);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_DUP_CTX_PROVIDER_API_TC001
 * @title  RSA CRYPT_EAL_PkeyDupCtx test for the default provider.
 * @precon Create the contexts of the rsa algorithm using the default provider, set para and generate a key pair.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyDupCtx mehod to dup rsa, expected result 1
 * @expect
 *    1. Success.
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_DUP_CTX_PROVIDER_API_TC001(Hex *e, int bits)
{
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyCtx *newPkey = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    SetRsaPara(&para, e->x, e->len, bits);

    TestMemInit();
    CRYPT_RandRegist(RandFunc);

    pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE+CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), 0);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    CRYPT_RSA_Ctx *rsaCtx = (CRYPT_RSA_Ctx *)pkey->key;
    ASSERT_TRUE(rsaCtx != NULL);

    newPkey = CRYPT_EAL_PkeyDupCtx(pkey);
    ASSERT_TRUE(newPkey != NULL);
    ASSERT_EQ(newPkey->references.count, 1);
    CRYPT_RSA_Ctx *rsaCtx2 = (CRYPT_RSA_Ctx *)newPkey->key;
    ASSERT_TRUE(rsaCtx2 != NULL);

    ASSERT_COMPARE("rsa compare n",
        rsaCtx->prvKey->n->data,
        rsaCtx->prvKey->n->size * sizeof(BN_UINT),
        rsaCtx2->prvKey->n->data,
        rsaCtx2->prvKey->n->size * sizeof(BN_UINT));

    ASSERT_COMPARE("rsa compare d",
        rsaCtx->prvKey->d->data,
        rsaCtx->prvKey->d->size * sizeof(BN_UINT),
        rsaCtx2->prvKey->d->data,
        rsaCtx2->prvKey->d->size * sizeof(BN_UINT));

exit:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(newPkey);
    CRYPT_EAL_RandDeinit();
}
/* END_CASE */


/**
 * @test   SDV_CRYPTO_RSA_GET_PUB_PROVIDER_API_TC001
 * @title  RSA CRYPT_EAL_PkeyGetPub test for the default provider.
 * @precon 1. Create the context of the rsa algorithm using the default provider.
 *         2. Initialize the DRBG.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyGetPub method without public key, expected result 1
 *    2. Set para and generate a key pair, expected result 2
 *    3. Call the CRYPT_EAL_PkeyGetPub method:
 *       (1) pkey = NULL, expected result 1.
 *       (2) pub = NULL, expected result 1.
 *       (3) n = NULL, expected result 1.
 *       (4) n != NULL and nLen = 0, expected result 3.
 *       (5) e = NULL, expected result 1.
 *       (6) e != NULL, eLen = 0, expected result 3.
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_SUCCESS
 *    3. CRYPT_BN_BUFF_LEN_NOT_ENOUGH
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_GET_PUB_PROVIDER_API_TC001(void)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    uint8_t e[] = {1, 0, 1};
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyPub pubKey = {0};
    uint8_t pubE[600];
    uint8_t pubN[600];

    SetRsaPara(&para, e, 3, 1024);
    SetRsaPubKey(&pubKey, pubE, 600, pubN, 600);  // 600 bytes > 1024 bits

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);

    /* Missing public key */
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(NULL, &pubKey), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, NULL), CRYPT_NULL_INPUT);

    /* n = NULL */
    pubKey.key.rsaPub.n = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_NULL_INPUT);
    pubKey.key.rsaPub.n = pubN;

    /* n != NULL and nLen = 0 */
    pubKey.key.rsaPub.nLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_BN_BUFF_LEN_NOT_ENOUGH);
    pubKey.key.rsaPub.nLen = 600;

    /* e = NULL */
    pubKey.key.rsaPub.e = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_NULL_INPUT);
    pubKey.key.rsaPub.e = pubE;

    /* e != NULL, eLen = 0 */
    pubKey.key.rsaPub.eLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey, &pubKey), CRYPT_BN_BUFF_LEN_NOT_ENOUGH);

exit:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_GET_PRV_PROVIDER_API_TC001
 * @title  RSA CRYPT_EAL_PkeyGetPrv: Bad private key for the default provider.
 * @precon 1. Create the context of the rsa algorithm using the default provider.
 *         2. Initialize the DRBG.
 * @brief
 *    1. Call the CRYPT_EAL_PkeyGetPrv method without private key, expected result 1
 *    2. Set para and generate a key pair, expected result 2
 *    3. Call the CRYPT_EAL_PkeyGetPrv method:
 *       (1) pkey = NULL, expected result 1.
 *       (2) prv = NULL, expected result 1.
 *       (3) p = NULL and q = NULL, expected result 2.
 *       (4) p = NULL and q != NULL, expected result 1.
 *       (5) p != NULL and q != NULL, expected result 2.
 *       (6) d = NULL, expected result 1.
 * @expect
 *    1. CRYPT_NULL_INPUT
 *    2. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_GET_PRV_PROVIDER_API_TC001(void)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPrv prvKey = {0};

    CRYPT_EAL_PkeyPara para = {0};
    uint8_t e[] = {1, 0, 1};
    uint8_t prvD[600];
    uint8_t prvN[600];
    uint8_t prvP[600];
    uint8_t prvQ[600];

    SetRsaPrvKey(&prvKey, prvN, 600, prvD, 600);
    SetRsaPara(&para, e, 3, 1024);

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);

    pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);

    /* Missing private key */
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(NULL, &prvKey), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, NULL), CRYPT_NULL_INPUT);

    /* p is NULL and q is NULL */
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_SUCCESS);

    /* p = NULL and q != NULL */
    prvKey.key.rsaPrv.q = prvQ;
    prvKey.key.rsaPrv.qLen = 600;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_NULL_INPUT);

    /* p != NULL and q != NULL */
    prvKey.key.rsaPrv.p = prvP;
    prvKey.key.rsaPrv.pLen = 600;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_SUCCESS);

    /* d = NULL */
    prvKey.key.rsaPrv.d = NULL;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvKey), CRYPT_NULL_INPUT);

exit:
    CRYPT_EAL_RandDeinit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */


/**
 * @test   SDV_CRYPTO_RSA_CMP_PROVIDER_API_TC001
 * @title  RSA: CRYPT_EAL_PkeyCmp invalid parameter test for the default provider.
 * @precon para id and public key.
 * @brief
 *    1. Create the contexts(ctx1, ctx2) of the rsa algorithm using the default provider, expected result 1
 *    2. Call the CRYPT_EAL_PkeyCmp to compare ctx1 and ctx2, expected result 2
 *    3. Set public key for ctx1, expected result 3
 *    4. Call the CRYPT_EAL_PkeyCmp to compare ctx1 and ctx2, expected result 4
 *    5. Set different public key for ctx2, expected result 5
 *    6. Call the CRYPT_EAL_PkeyCmp to compare ctx1 and ctx2, expected result 6
 * @expect
 *    1. Success, and contexts are not NULL.
 *    2. CRYPT_RSA_NO_KEY_INFO
 *    3. CRYPT_SUCCESS
 *    4. CRYPT_RSA_NO_KEY_INFO
 *    5. CRYPT_SUCCESS
 *    6. CRYPT_RSA_PUBKEY_NOT_EQUAL
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_CMP_PROVIDER_API_TC001(Hex *n, Hex *e)
{
    uint8_t tmpE[] = {1, 0, 1};
    CRYPT_EAL_PkeyPub pub = {0};
    SetRsaPubKey(&pub, n->x, n->len, e->x, e->len);

    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx1 = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    CRYPT_EAL_PkeyCtx *ctx2 = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(ctx1 != NULL && ctx2 != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_RSA_NO_KEY_INFO);  // no key

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx1, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_RSA_NO_KEY_INFO);  // ctx2 no pubkey

    SetRsaPubKey(&pub, n->x, n->len, tmpE, 3);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx2, &pub), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx1, ctx2), CRYPT_RSA_PUBKEY_NOT_EQUAL);

exit:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_SET_PARAEX_API_TC001
 * @title  RSA CRYPT_EAL_PkeySetParaEx: The e value of para is invalid.
 * @precon Create the contexts of the rsa algorithm.
 * @brief
 *    1. Call the CRYPT_EAL_PkeySetParaEx method:
 *       (1) e = NULL, expected result 1.
 *       (2) e len = 0, expected result 1.
 *       (3) e = 0, expected result 2.
 *       (4) e is even, expected result 2.
 *       (5) e len = 1025, expected result 1.
 * @expect
 *    1. CRYPT_EAL_ERR_NEW_PARA_FAIL
 *    2. CRYPT_RSA_ERR_E_VALUE
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SET_PARAEX_API_TC001(void)
{
    uint8_t e[] = {1, 0, 1};
    uint8_t e2[] = {1, 0};
    uint8_t e0[] = {0, 0, 0};
    uint8_t longE[1025] = {0};
    longE[0] = 0x01;
    longE[1024] = 0x01;  // The tail of 1024 is set to 1.
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    SetRsaPara(&para, e, 3, 1024);  // bits: 1024 is valid
    CRYPT_Param param;
    param.param = &(para.para.rsaPara);
    param.paramLen = sizeof(para.para.rsaPara);
    TestMemInit();

    pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);

    para.para.rsaPara.e = NULL;
    param.param = &(para.para.rsaPara);
    ASSERT_TRUE_AND_LOG("e = NULL", CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

    para.para.rsaPara.eLen = 0;
    param.param = &(para.para.rsaPara);
    ASSERT_TRUE_AND_LOG("e len = 0", CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

    para.para.rsaPara.e = e0;
    para.para.rsaPara.eLen = 1;
    param.param = &(para.para.rsaPara);
    ASSERT_TRUE_AND_LOG("e = 0", CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_RSA_ERR_E_VALUE);

    para.para.rsaPara.eLen = 2;
    para.para.rsaPara.e = e2;
    param.param = &(para.para.rsaPara);
    ASSERT_TRUE_AND_LOG("e is even", CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_RSA_ERR_E_VALUE);

    para.para.rsaPara.eLen = 1025;  // 1025 is invalid, but the length is sufficient.
    para.para.rsaPara.e = longE;
    param.param = &(para.para.rsaPara);
    ASSERT_TRUE_AND_LOG("e len = 1025", CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_EAL_ERR_NEW_PARA_FAIL);

exit:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_SET_PARAEX_API_TC002
 * @title  RSA CRYPT_EAL_PkeySetParaEx: The bits value of para is invalid.
 * @precon Create the contexts of the rsa algorithm.
 * @brief
 *    1. Call the CRYPT_EAL_PkeySetPara method with invalid bits, expected result 1.
 * @expect
 *    1. CRYPT_EAL_ERR_NEW_PARA_FAIL
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SET_PARAEX_API_TC002(int bits)
{
    uint8_t e[] = {1, 0, 1};
    CRYPT_EAL_PkeyPara para = {0};

    SetRsaPara(&para, e, 3, bits);  // eLen = 3
    CRYPT_Param param;
    param.param = &(para.para.rsaPara);
    param.paramLen = sizeof(para.para.rsaPara);
    TestMemInit();

    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaEx(pkey, &param), CRYPT_EAL_ERR_NEW_PARA_FAIL);
exit:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_RSA_SET_PARAEX_API_TC003
 * @title  RSA CRYPT_EAL_PkeySetParaEx: Success.
 * @precon Create the contexts of the rsa algorithm.
 * @brief
 *    1. Call the CRYPT_EAL_PkeySetPara method, key len is 1024|1025|5120|16384 bits, expected result 1.
 * @expect
 *    1. CRYPT_SUCCESS
 */
/* BEGIN_CASE */
void SDV_CRYPTO_RSA_SET_PARAEX_API_TC003(void)
{
    uint8_t e3[] = {1, 0, 1};
    uint8_t e5[] = {1, 0, 0, 0, 1};
    uint8_t e7[] = {1, 0, 0, 0, 0, 0, 1};
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    TestMemInit();

    pkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_KEYMGMT_OPERATE, "provider=default");
    ASSERT_TRUE(pkey != NULL);

    SetRsaPara(&para, e3, 3, 1024);  // Valid parameters: elen = 3, bits =1024
    CRYPT_Param param;
    param.param = &(para.para.rsaPara);
    param.paramLen = sizeof(para.para.rsaPara);
    ASSERT_TRUE_AND_LOG("1k key", CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_SUCCESS);
    
    para.para.rsaPara.bits = 1025;
    param.param = &(para.para.rsaPara);
    ASSERT_TRUE_AND_LOG("1025 bits key", CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_SUCCESS);

    SetRsaPara(&para, e5, 5, 5120);
    param.param = &(para.para.rsaPara);
    ASSERT_TRUE_AND_LOG("5k key", CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_SUCCESS);

    SetRsaPara(&para, e7, 7, 16384);
    param.param = &(para.para.rsaPara);
    ASSERT_TRUE_AND_LOG("16k key", CRYPT_EAL_PkeySetParaEx(pkey, &param) == CRYPT_SUCCESS);

exit:
    CRYPT_EAL_PkeyFreeCtx(pkey);
}
/* END_CASE */