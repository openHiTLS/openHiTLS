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
#ifdef HITLS_CRYPTO_CMVP

#include <string.h>
#include "crypt_cmvp_selftest.h"
#include "cmvp_common.h"
#include "err.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "bsl_err_internal.h"
#include "crypt_params_key.h"
#include "crypt_utils.h"
#include "crypt_eal_rand.h"
#include "securec.h"
#include "bsl_sal.h"

#define PKCSV15_PAD 0
#define PSS_PAD 1
#define OAEP_PAD 2

typedef struct {
    const char *n;
    const char *e;
    const char *d;
    const char *salt;
    const char *msg;
    const char *sign;
    CRYPT_MD_AlgId mdId;
} CMVP_RSA_VECTOR;

// 与CRYPT_EAL_PkeyPadId顺序一致
static const CMVP_RSA_VECTOR RSA_VECTOR[] = {
    // RSA-2048bits-SHA224 PKCS#1 Ver 1.5
    // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Digital-Signatures#rsa2vs
    {
        .n = "e0b14b99cd61cd3db9c2076668841324fa3174f33ce66ffd514394d34178d29a49493276b6777233"
            "e7d46a3e68bc7ca7e899e901d54f6dee0749c3e48ddf68685867ee2ae66df88eb563f6db137a9f6b"
            "175a112e0eda8368e88e45efe1ce14bc6016d52639627066af1872c72f60b9161c1d237eeb34b0f8"
            "41b3f0896f9fe0e16b0f74352d101292cc464a7e7861bbeb86f6df6151cb265417c66c565ed8974b"
            "d8fc984d5ddfd4eb91a3d5234ce1b5467f3ade375f802ec07293f1236efa3068bc91b158551c875c"
            "5dc0a9d6fa321bf9421f08deac910e35c1c28549ee8eed8330cf70595ff70b94b49907e27698a9d9"
            "11f7ac0706afcb1a4a39feb38b0a8049",
        .e = "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000010001",
        .d = "1dbca92e4245c2d57bfba76210cc06029b502753b7c821a32b799fbd33c98b49db10226b1eac0143"
            "c8574ef652833b96374d034ef84daa5559c693f3f028d49716b82e87a3f682f25424563bd9409dcf"
            "9d08110500f73f74076f28e75e0199b1f29fa2f70b9a31190dec54e872a740e7a1b1e38c3d11bca8"
            "267deb842cef4262237ac875725068f32563b478aca8d6a99f34cb8876b97145b2e8529ec8adea83"
            "ead4ec63e3ff2d17a2ffefb05c902ca7a92168378c89f75c928fc4f0707e43487a4f47df70cae87e"
            "24272c136d3e98cf59066d41a3d038857d073d8b4d2c27b8f0ea6bfa50d263091a4a18c63f446bc9"
            "a61e8c4a688347b2435ec8e72eddaea7",
        .salt = NULL,
        .msg = "79bcffbfd6bcf638934b38e47a1b821dc97cafe1da757f820313989ebc01ca52ff5997abf5baf35d"
            "ce9b48b8f0debdd755a8b81b2e71a1d8cd57ea4dc1b84cda43ff536dd1be1c3e18fe5ebc17d3a7c6"
            "8233e81f6407341c0983c5a01bb3404a0b5739edb2f1fa41391c80d8361fc75317c248d5c461bfb8"
            "803e317f101b2e0c",
        .sign = "5cbc1d2c696e7c5c0a538db35a793959008564c43d9aa8ed20816b66ef77124eca7584631308d0fd"
            "7383be62eaf799b5e67e8874cc9d88d507e1bd4fb9fd7517adebe5d583b075040ce3db2affcf77ee"
            "0162be2e575413f455841cb6ea4a30595daee45e3042b0b9d8f9ee700df3f1898219777c21ef3695"
            "af95628ae64260dd2cb7ee6270fb06f52ea1aea72e1a26a26f2e7cee560ae0cb8be323113c3f19c9"
            "7cb5a3e61b998a68432aa2d1f8c8c00ac92b0f35344710ae1d6d79f379fbb3dba41b46b9c814eb3a"
            "25ca64a3ff86af613d163f941a897676652e7c3f6769fd964b862dc58cc2e652d0a404e94853fb83"
            "937c862c1df2df9fd297f058bf660d15",
        .mdId = CRYPT_MD_SHA224
    },
    // RSA-2048bits-SHA224 PKCS#1 RSASSA-PSS
    // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Digital-Signatures#rsa2vs
    {
        .n = "d95b71c9dfee453ba1b1a7de2c1f0b0a67579ee91d1d3ad97e481829b86edac750c48e12a8cdb026"
            "c82f273dafc222009f0db3b08b2db10a69c4b2dddaaeceac1b0c862682eef294e579f55aab871bc0"
            "a7eeabc923c9e80dddc22ec0a27002aee6a5ba66397f412bbaf5fb4eaf66a1a0f82eaf6827198caf"
            "49b347258b1283e8cbb10da2837f6ecc3490c728fe927f44455a6f194f3776bf79151d9ad7e2daf7"
            "70b37d12627cc0c5fb62484f46258d9ce2c11b26256d09cb412f8d8f8f1fe91bb94ac27de6d26a83"
            "a8439e51b35dbee46b3b8ff991d667bb53eeee85ff1652c8981f141d47c8205791cef5b32d718ddc"
            "082ed0dd542826416b2271064ef437a9",
        .e = "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000010001",
        .d = "2f21b01be94dde7f5ec18a3817f3274ebb37f9c26cc8c0d1169c05794e7fe33ae31dabfd09d38845"
            "f094a0fab458f14c9730be6d22d0e699ee7373a1bde0b7fa03e784536782eee1309d708197be355b"
            "624ed3bb4ae2664a5372def67082bf6233ab6e2eea7ad8a3e5e79ef5e1fcec415e6fa923798f05bd"
            "a0ca9a3bdedb45f4d781ef1a4f5075cd9bb399635da3e9a6880ed021a750bc9806af81fbffcd4ace"
            "af804ec76808ae186715c772caa961a862991c67ca8bffef6b34087b44db5b59abce09317747fc75"
            "252f1705260b13dd62ccbc745091f3c1b64f59031d340c7362a0e1066ab0554d466f209a3cf51bc6"
            "4b3c70c3ce52f413d81b228fa31d9efd",
        .salt = "6f2841166a64471d4f0b8ed0dbb7db32161da13b",
        .msg = "e2b81456c355c3f80a363a85cbf245e85a5ff2435e5548d627b5362242aaca4e4a2fa4c900d2a931"
            "9eb7fc7469df2a3586aaa4710e9b7362655c27a3c70210962391b1032dc37201af05951a1fc36baa"
            "77e5c888419ab4e8f1546380781468ea16e7254a70b08630e229efc016257210d61846d11ed87432"
            "76a5d4017e683813",
        .sign = "cd1fe0acb89969ae139c178bfef1cc982993521b3a020ec847c89c0cc6c869d970f43f018d495b9e"
            "991457e7501a344c33c376fd2efcf05ad6eb2bd0b3c0e7cc3c88a4124398ca16585490a0817a3614"
            "9cc82cdc01b20e9026261215dd06f9db4e13613c6a569c2187a0e00bc63c281149433ac7f061bd21"
            "8e79f8eca9dd9c93ebc3cc013bf27aa0bf286e124593e76d3c7012f97ae1d0c4bf5823cf17fe76d5"
            "05a54cef174add58ae616f47de825049e9916bf2ab7de4d443745763b0c314cfae3a6e57ad475cc5"
            "fae47cddcad7b526c2154a15f9ee8eab02f4c36f7a41d7a19b23c5996b627270ceb2c0dbed1a6b6d"
            "d2ff94868e073cb7b1a1fa3429e487ae",
        .mdId = CRYPT_MD_SHA224
    },
};

static bool GetPrvKey(CMVP_RSA_VECTOR vector, CRYPT_EAL_PkeyPrv *prv)
{
    (void)memset_s(&prv->key.rsaPrv, sizeof(prv->key.rsaPrv), 0, sizeof(prv->key.rsaPrv));
    prv->key.rsaPrv.n = CMVP_StringsToBins(vector.n, &(prv->key.rsaPrv.nLen));
    GOTO_EXIT_IF(prv->key.rsaPrv.n == NULL, CRYPT_CMVP_COMMON_ERR);
    prv->key.rsaPrv.d = CMVP_StringsToBins(vector.d, &(prv->key.rsaPrv.dLen));
    GOTO_EXIT_IF(prv->key.rsaPrv.d == NULL, CRYPT_CMVP_COMMON_ERR);
    prv->id = CRYPT_PKEY_RSA;

    return true;
EXIT:
    return false;
}

static bool GetPubKey(CMVP_RSA_VECTOR vector, CRYPT_EAL_PkeyPub *pub)
{
    pub->key.rsaPub.n = CMVP_StringsToBins(vector.n, &(pub->key.rsaPub.nLen));
    GOTO_EXIT_IF(pub->key.rsaPub.n == NULL, CRYPT_CMVP_COMMON_ERR);
    pub->key.rsaPub.e = CMVP_StringsToBins(vector.e, &(pub->key.rsaPub.eLen));
    GOTO_EXIT_IF(pub->key.rsaPub.e == NULL, CRYPT_CMVP_COMMON_ERR);
    pub->id = CRYPT_PKEY_RSA;
    return true;
EXIT:
    return false;
}

static bool SetPkcsv15Pad(CRYPT_EAL_PkeyCtx *pkey, uint32_t *hashId)
{
    *hashId = RSA_VECTOR[PKCSV15_PAD].mdId;
    GOTO_EXIT_IF(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, hashId, sizeof(uint32_t)) !=
        CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    return true;
EXIT:
    return false;
}

static bool SetPssPad(CRYPT_EAL_PkeyCtx *pkey, uint32_t saltLen)
{
    uint32_t mdId = RSA_VECTOR[PSS_PAD].mdId;
    uint32_t mgfId = RSA_VECTOR[PSS_PAD].mdId;
    BSL_Param pss[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, (void *)(uintptr_t)&mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, (void *)(uintptr_t)&mgfId, sizeof(mgfId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, (void *)(uintptr_t)&saltLen, sizeof(saltLen), 0},
        BSL_PARAM_END
    };
    GOTO_EXIT_IF(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PSS, pss, 0) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    return true;
EXIT:
    return false;
}

static bool RsaSelftestSign(void *libCtx, const char *attrName, int32_t id)
{
    bool ret = false;
    uint8_t *salt = NULL;
    uint32_t pkcsv15;
    CRYPT_EAL_PkeyPrv prv = { 0 };
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    uint8_t *msg = NULL;
    uint8_t *expectSign = NULL;
    uint8_t *sign = NULL;
    uint32_t msgLen, expectSignLen, signLen, saltLen;

    msg = CMVP_StringsToBins(RSA_VECTOR[id].msg, &msgLen);
    GOTO_EXIT_IF(msg == NULL, CRYPT_CMVP_COMMON_ERR);
    expectSign = CMVP_StringsToBins(RSA_VECTOR[id].sign, &expectSignLen);
    GOTO_EXIT_IF(expectSign == NULL, CRYPT_CMVP_COMMON_ERR);

    pkey = (libCtx != NULL) ? CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_RSA, 0, attrName) :
        CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    GOTO_EXIT_IF(pkey == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(GetPrvKey(RSA_VECTOR[id], &prv) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(CRYPT_EAL_PkeySetPrv(pkey, &prv) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    signLen = CRYPT_EAL_PkeyGetSignLen(pkey);
    sign = BSL_SAL_Malloc(sizeof(uint32_t) * signLen);
    GOTO_EXIT_IF(sign == NULL, CRYPT_MEM_ALLOC_FAIL);
    if (id == PKCSV15_PAD) {
        GOTO_EXIT_IF(!SetPkcsv15Pad(pkey, &pkcsv15), CRYPT_CMVP_ERR_ALGO_SELFTEST);
    } else {
        salt = CMVP_StringsToBins(RSA_VECTOR[PSS_PAD].salt, &(saltLen));
        GOTO_EXIT_IF(salt == NULL, CRYPT_CMVP_COMMON_ERR);
        GOTO_EXIT_IF(!SetPssPad(pkey, saltLen), CRYPT_CMVP_ERR_ALGO_SELFTEST);
        GOTO_EXIT_IF(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_SALT, salt, saltLen) !=
            CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }
    GOTO_EXIT_IF(CRYPT_EAL_PkeySign(pkey, RSA_VECTOR[id].mdId, msg, msgLen, sign, &signLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(signLen != expectSignLen, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(memcmp(expectSign, sign, signLen) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret = true;
EXIT:
    BSL_SAL_Free(salt);
    BSL_SAL_Free(msg);
    BSL_SAL_Free(sign);
    BSL_SAL_Free(expectSign);
    BSL_SAL_Free(prv.key.rsaPrv.n);
    BSL_SAL_Free(prv.key.rsaPrv.d);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return ret;
}

static bool RsaSelftestVerify(void *libCtx, const char *attrName, int32_t id)
{
    bool ret = false;
    uint8_t *salt = NULL;
    uint32_t mdId;
    CRYPT_EAL_PkeyPub pub = { 0 };
    uint8_t *msg = NULL;
    uint8_t *sign = NULL;
    uint32_t signLen, msgLen, saltLen;
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    msg = CMVP_StringsToBins(RSA_VECTOR[id].msg, &msgLen);
    GOTO_EXIT_IF(msg == NULL, CRYPT_CMVP_COMMON_ERR);
    sign = CMVP_StringsToBins(RSA_VECTOR[id].sign, &signLen);
    GOTO_EXIT_IF(sign == NULL, CRYPT_CMVP_COMMON_ERR);

    pkey = (libCtx != NULL) ? CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_RSA, 0, attrName) :
        CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    GOTO_EXIT_IF(pkey == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(GetPubKey(RSA_VECTOR[id], &pub) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(CRYPT_EAL_PkeySetPub(pkey, &pub) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    if (id == PKCSV15_PAD) {
        GOTO_EXIT_IF(!SetPkcsv15Pad(pkey, &mdId), CRYPT_CMVP_ERR_ALGO_SELFTEST);
    } else {
        salt = CMVP_StringsToBins(RSA_VECTOR[PSS_PAD].salt, &(saltLen));
        GOTO_EXIT_IF(salt == NULL, CRYPT_CMVP_COMMON_ERR);
        GOTO_EXIT_IF(!SetPssPad(pkey, saltLen), CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }
    GOTO_EXIT_IF(CRYPT_EAL_PkeyVerify(pkey, RSA_VECTOR[id].mdId, msg, msgLen, sign, signLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = true;
EXIT:
    BSL_SAL_Free(salt);
    BSL_SAL_Free(msg);
    BSL_SAL_Free(sign);
    BSL_SAL_Free(pub.key.rsaPub.n);
    BSL_SAL_Free(pub.key.rsaPub.e);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return ret;
}

static bool RsaSelftestEncrypt(int32_t id)
{
    bool ret = false;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyPub pub = { 0 };
    CRYPT_EAL_PkeyPrv prv = { 0 };
    const uint8_t msg[] = { 0x01, 0x02, 0x03, 0x04 };
    uint8_t cTxt[1024] = { 0 };
    uint32_t cTxtLen = sizeof(cTxt);
    uint8_t pTxt[1024] = { 0 };
    uint32_t pTxtLen = sizeof(pTxt);
    int32_t err = CRYPT_CMVP_ERR_ALGO_SELFTEST;
    uint32_t mdId = CRYPT_MD_SHA256;
    BSL_Param oaep[3] = {{CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        BSL_PARAM_END
    };

    // encrypt
    pubCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    GOTO_EXIT_IF(pubCtx == NULL, err);
    GOTO_EXIT_IF(GetPubKey(RSA_VECTOR[0], &pub) != true, err);
    GOTO_EXIT_IF(CRYPT_EAL_PkeySetPub(pubCtx, &pub) != CRYPT_SUCCESS, err);
    if (id == PKCSV15_PAD) {
        GOTO_EXIT_IF(CRYPT_EAL_PkeyCtrl(pubCtx, CRYPT_CTRL_SET_RSA_RSAES_PKCSV15, &mdId, sizeof(mdId)) != CRYPT_SUCCESS,
            err);
    } else {
        GOTO_EXIT_IF(CRYPT_EAL_PkeyCtrl(pubCtx, CRYPT_CTRL_SET_RSA_RSAES_OAEP, oaep, 0) != CRYPT_SUCCESS, err);
    }
    GOTO_EXIT_IF(CRYPT_EAL_PkeyEncrypt(pubCtx, msg, sizeof(msg), cTxt, &cTxtLen) != CRYPT_SUCCESS, err);

    // decrypt
    prvCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    GOTO_EXIT_IF(prvCtx == NULL, err);
    GOTO_EXIT_IF(GetPrvKey(RSA_VECTOR[0], &prv) != true, err);
    GOTO_EXIT_IF(CRYPT_EAL_PkeySetPrv(prvCtx, &prv) != CRYPT_SUCCESS, err);
    if (id == PKCSV15_PAD) {
        GOTO_EXIT_IF(CRYPT_EAL_PkeyCtrl(prvCtx, CRYPT_CTRL_SET_RSA_RSAES_PKCSV15, &mdId,
            sizeof(mdId)) != CRYPT_SUCCESS, err);
    } else {
        GOTO_EXIT_IF(CRYPT_EAL_PkeyCtrl(prvCtx, CRYPT_CTRL_SET_RSA_RSAES_OAEP, oaep, 0) != CRYPT_SUCCESS, err);
    }
    GOTO_EXIT_IF(CRYPT_EAL_PkeyDecrypt(prvCtx, cTxt, cTxtLen, pTxt, &pTxtLen) != CRYPT_SUCCESS, err);

    GOTO_EXIT_IF(memcmp(msg, pTxt, pTxtLen) != 0, err);
    ret = true;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    BSL_SAL_Free(pub.key.rsaPub.n);
    BSL_SAL_Free(pub.key.rsaPub.e);
    BSL_SAL_Free(prv.key.rsaPrv.n);
    BSL_SAL_Free(prv.key.rsaPrv.d);
    return ret;
}

bool CRYPT_CMVP_SelftestProviderRsa(void *libCtx, const char *attrName)
{
    GOTO_EXIT_IF(RsaSelftestSign(libCtx, attrName, PKCSV15_PAD) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(RsaSelftestVerify(libCtx, attrName, PKCSV15_PAD) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(RsaSelftestSign(libCtx, attrName, PSS_PAD) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(RsaSelftestVerify(libCtx, attrName, PSS_PAD) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    return true;
EXIT:
    return false;
}

bool CRYPT_CMVP_SelftestRsa(void)
{
    GOTO_EXIT_IF(RsaSelftestSign(NULL, NULL, PKCSV15_PAD) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(RsaSelftestVerify(NULL, NULL, PKCSV15_PAD) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(RsaSelftestSign(NULL, NULL, PSS_PAD) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(RsaSelftestVerify(NULL, NULL, PSS_PAD) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(RsaSelftestEncrypt(OAEP_PAD) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(RsaSelftestEncrypt(PKCSV15_PAD) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    return true;
EXIT:
    return false;
}

#endif
