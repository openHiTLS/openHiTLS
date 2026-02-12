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
#if defined(HITLS_CRYPTO_CMVP_ISO19790) || defined(HITLS_CRYPTO_CMVP_FIPS)

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
#include "crypt_util_rand.h"
#include "securec.h"
#include "bsl_sal.h"

#define PKCSV15_PAD 0
#define PSS_PAD 1
#define OAEP_PAD 2
#define MAX_CIPHER_TEXT_LEN 512

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

typedef struct {
    const char *n;
    const char *e;
    const char *d;
    const char *seed;
    const char *msg;
    const char *cipher;
    CRYPT_MD_AlgId mdId;
} CMVP_RSA_ENC_DEC_VECTOR;

// Test vectors sourced from the pyca/cryptography project.
static const CMVP_RSA_ENC_DEC_VECTOR RSA_ENC_DEC_VECTOR = {
    .n = "ae45ed5601cec6b8cc05f803935c674ddbe0d75c4c09fd7951fc6b0caec313a8"
         "df39970c518bffba5ed68f3f0d7f22a4029d413f1ae07e4ebe9e4177ce23e7f5"
         "404b569e4ee1bdcf3c1fb03ef113802d4f855eb9b5134b5a7c8085adcae6fa2f"
         "a1417ec3763be171b0c62b760ede23c12ad92b980884c641f5a8fac26bdad4a0"
         "3381a22fe1b754885094c82506d4019a535a286afeb271bb9ba592de18dcf600"
         "c2aeeae56e02f7cf79fc14cf3bdc7cd84febbbf950ca90304b2219a7aa063aef"
         "a2c3c1980e560cd64afe779585b6107657b957857efde6010988ab7de417fc88"
         "d8f384c4e6e72c3f943e0c31c0c4a5cc36f879d8a3ac9d7d59860eaada6b83bb",
    .e = "010001",
    .d = "056b04216fe5f354ac77250a4b6b0c8525a85c59b0bd80c56450a22d5f438e59"
         "6a333aa875e291dd43f48cb88b9d5fc0d499f9fcd1c397f9afc070cd9e398c8d"
         "19e61db7c7410a6b2675dfbf5d345b804d201add502d5ce2dfcb091ce9997bbe"
         "be57306f383e4d588103f036f7e85d1934d152a323e4a8db451d6f4a5b1b0f10"
         "2cc150e02feee2b88dea4ad4c1baccb24d84072d14e1d24a6771f7408ee30564"
         "fb86d4393a34bcf0b788501d193303f13a2284b001f0f649eaf79328d4ac5c43"
         "0ab4414920a9460ed1b7bc40ec653e876d09abc509ae45b525190116a0c26101"
         "848298509c1c3bf3a483e7274054e15e97075036e989f60932807b5257751e79",

    .msg = "8bba6bf82a6c0f86d5f1756e97956870b08953b06b4eb205bc1694ee",
    .seed = "47e1ab7119fee56c95ee5eaad86f40d0aa63bd33",
    .cipher = "53ea5dc08cd260fb3b858567287fa91552c30b2febfba213f0ae87702d068d19"
              "bab07fe574523dfb42139d68c3c5afeee0bfe4cb7969cbf382b804d6e6139614"
              "4e2d0e60741f8993c3014b58b9b1957a8babcd23af854f4c356fb1662aa72bfc"
              "c7e586559dc4280d160c126785a723ebeebeff71f11594440aaef87d10793a87"
              "74a239d4a04c87fe1467b9daf85208ec6c7255794a96cc29142f9a8bd418e3c1"
              "fd67344b0cd0829df3b2bec60253196293c6b34d3f75d32f213dd45c6273d505"
              "adf4cced1057cb758fc26aeefa441255ed4e64c199ee075e7f16646182fdb464"
              "739b68ab5daff0e63e9552016824f054bf4d3c8c90a97bb6b6553284eb429fcc",
    .mdId = CRYPT_MD_SHA1,
};

static bool GetPrvKey(const char *n, const char *d, CRYPT_EAL_PkeyPrv *prv)
{
    (void)memset_s(&prv->key.rsaPrv, sizeof(prv->key.rsaPrv), 0, sizeof(prv->key.rsaPrv));
    prv->key.rsaPrv.n = CMVP_StringsToBins(n, &(prv->key.rsaPrv.nLen));
    GOTO_ERR_IF_TRUE(prv->key.rsaPrv.n == NULL, CRYPT_CMVP_COMMON_ERR);
    prv->key.rsaPrv.d = CMVP_StringsToBins(d, &(prv->key.rsaPrv.dLen));
    GOTO_ERR_IF_TRUE(prv->key.rsaPrv.d == NULL, CRYPT_CMVP_COMMON_ERR);
    prv->id = CRYPT_PKEY_RSA;

    return true;
ERR:
    return false;
}

static bool GetPubKey(const char *n, const char *e, CRYPT_EAL_PkeyPub *pub)
{
    pub->key.rsaPub.n = CMVP_StringsToBins(n, &(pub->key.rsaPub.nLen));
    GOTO_ERR_IF_TRUE(pub->key.rsaPub.n == NULL, CRYPT_CMVP_COMMON_ERR);
    pub->key.rsaPub.e = CMVP_StringsToBins(e, &(pub->key.rsaPub.eLen));
    GOTO_ERR_IF_TRUE(pub->key.rsaPub.e == NULL, CRYPT_CMVP_COMMON_ERR);
    pub->id = CRYPT_PKEY_RSA;
    return true;
ERR:
    return false;
}

static bool SetPkcsv15Pad(CRYPT_EAL_PkeyCtx *pkey, int32_t *hashId)
{
    *hashId = RSA_VECTOR[PKCSV15_PAD].mdId;
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, hashId, sizeof(int32_t)) !=
        CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    return true;
ERR:
    return false;
}

static bool SetPssPad(CRYPT_EAL_PkeyCtx *pkey, uint32_t saltLen)
{
    CRYPT_MD_AlgId mdId = RSA_VECTOR[PSS_PAD].mdId;
    CRYPT_MD_AlgId mgfId = RSA_VECTOR[PSS_PAD].mdId;
    BSL_Param pss[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, (void *)(uintptr_t)&mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, (void *)(uintptr_t)&mgfId, sizeof(mgfId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, (void *)(uintptr_t)&saltLen, sizeof(saltLen), 0},
        BSL_PARAM_END
    };
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PSS, pss, 0) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    return true;
ERR:
    return false;
}

static bool RsaSelftestSign(void *libCtx, const char *attrName, int32_t id)
{
    bool ret = false;
    uint8_t *salt = NULL;
    int32_t pkcsv15;
    CRYPT_EAL_PkeyPrv prv = { 0 };
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    uint8_t *msg = NULL;
    uint8_t *expectSign = NULL;
    uint8_t *sign = NULL;
    uint32_t msgLen, expectSignLen, signLen, saltLen;

    msg = CMVP_StringsToBins(RSA_VECTOR[id].msg, &msgLen);
    GOTO_ERR_IF_TRUE(msg == NULL, CRYPT_CMVP_COMMON_ERR);
    expectSign = CMVP_StringsToBins(RSA_VECTOR[id].sign, &expectSignLen);
    GOTO_ERR_IF_TRUE(expectSign == NULL, CRYPT_CMVP_COMMON_ERR);

    pkey = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_RSA, 0, attrName);
    GOTO_ERR_IF_TRUE(pkey == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(GetPrvKey(RSA_VECTOR[id].n, RSA_VECTOR[id].d, &prv) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPrv(pkey, &prv) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    signLen = CRYPT_EAL_PkeyGetSignLen(pkey);
    sign = BSL_SAL_Malloc(sizeof(uint32_t) * signLen);
    GOTO_ERR_IF_TRUE(sign == NULL, CRYPT_MEM_ALLOC_FAIL);
    if (id == PKCSV15_PAD) {
        GOTO_ERR_IF_TRUE(!SetPkcsv15Pad(pkey, &pkcsv15), CRYPT_CMVP_ERR_ALGO_SELFTEST);
    } else {
        salt = CMVP_StringsToBins(RSA_VECTOR[PSS_PAD].salt, &(saltLen));
        GOTO_ERR_IF_TRUE(salt == NULL, CRYPT_CMVP_COMMON_ERR);
        GOTO_ERR_IF_TRUE(!SetPssPad(pkey, saltLen), CRYPT_CMVP_ERR_ALGO_SELFTEST);
        GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_SALT, salt, saltLen) !=
            CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySign(pkey, RSA_VECTOR[id].mdId, msg, msgLen, sign, &signLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(signLen != expectSignLen, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(memcmp(expectSign, sign, signLen) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret = true;
ERR:
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
    int32_t mdId;
    CRYPT_EAL_PkeyPub pub = { 0 };
    uint8_t *msg = NULL;
    uint8_t *sign = NULL;
    uint32_t signLen, msgLen, saltLen;
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    msg = CMVP_StringsToBins(RSA_VECTOR[id].msg, &msgLen);
    GOTO_ERR_IF_TRUE(msg == NULL, CRYPT_CMVP_COMMON_ERR);
    sign = CMVP_StringsToBins(RSA_VECTOR[id].sign, &signLen);
    GOTO_ERR_IF_TRUE(sign == NULL, CRYPT_CMVP_COMMON_ERR);

    pkey = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_RSA, 0, attrName);
    GOTO_ERR_IF_TRUE(pkey == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(GetPubKey(RSA_VECTOR[id].n, RSA_VECTOR[id].e, &pub) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPub(pkey, &pub) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    if (id == PKCSV15_PAD) {
        GOTO_ERR_IF_TRUE(!SetPkcsv15Pad(pkey, &mdId), CRYPT_CMVP_ERR_ALGO_SELFTEST);
    } else {
        salt = CMVP_StringsToBins(RSA_VECTOR[PSS_PAD].salt, &(saltLen));
        GOTO_ERR_IF_TRUE(salt == NULL, CRYPT_CMVP_COMMON_ERR);
        GOTO_ERR_IF_TRUE(!SetPssPad(pkey, saltLen), CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyVerify(pkey, RSA_VECTOR[id].mdId, msg, msgLen, sign, signLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = true;
ERR:
    BSL_SAL_Free(salt);
    BSL_SAL_Free(msg);
    BSL_SAL_Free(sign);
    BSL_SAL_Free(pub.key.rsaPub.n);
    BSL_SAL_Free(pub.key.rsaPub.e);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return ret;
}

static int32_t SetRandomVector(const char *vector, uint8_t *r, uint32_t rLen)
{
    uint8_t *rand = NULL;
    uint32_t randLen;

    rand = CMVP_StringsToBins(vector, &randLen);
    if (rand == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (randLen < rLen) {
        BSL_SAL_FREE(rand);
        return CRYPT_CMVP_ERR_ALGO_SELFTEST;
    }
    (void)memcpy_s(r, rLen, rand, rLen);
    BSL_SAL_FREE(rand);
    return CRYPT_SUCCESS;
}

static int32_t TestVectorRandom(uint8_t *r, uint32_t rLen)
{
    return SetRandomVector(RSA_ENC_DEC_VECTOR.seed, r, rLen);
}

static bool RsaSelftestEncrypt(void *libCtx, const char *attrName, const uint8_t *plain, const uint32_t plainLen,
    const uint8_t *cipher, const uint32_t cipherLen)
{
    bool ret = false;
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyPub pub = { 0 };
    uint8_t cipherText[MAX_CIPHER_TEXT_LEN] = {0};
    uint32_t cipherTextLen = sizeof(cipherText);
    int32_t err = CRYPT_CMVP_ERR_ALGO_SELFTEST;
    CRYPT_MD_AlgId mdId = RSA_ENC_DEC_VECTOR.mdId;
    BSL_Param oaep[3] = {{CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        BSL_PARAM_END
    };
    CRYPT_EAL_RandFunc func = CRYPT_RandRegistGet();
    CRYPT_EAL_RandFuncEx funcEx = CRYPT_RandRegistExGet();
    CRYPT_RandRegistEx(NULL);
    CRYPT_RandRegist(TestVectorRandom);

    // encrypt
    pubCtx = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_RSA, 0, attrName);
    GOTO_ERR_IF_TRUE(pubCtx == NULL, err);
    GOTO_ERR_IF_TRUE(GetPubKey(RSA_ENC_DEC_VECTOR.n, RSA_ENC_DEC_VECTOR.e, &pub) != true, err);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPub(pubCtx, &pub) != CRYPT_SUCCESS, err);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyCtrl(pubCtx, CRYPT_CTRL_SET_RSA_RSAES_OAEP, oaep, 0) != CRYPT_SUCCESS, err);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyEncrypt(pubCtx, plain, plainLen, cipherText, &cipherTextLen) != CRYPT_SUCCESS, err);

    GOTO_ERR_IF_TRUE(cipherTextLen != cipherLen, err);
    GOTO_ERR_IF_TRUE(memcmp(cipher, cipherText, cipherTextLen) != 0, err);

    ret = true;
ERR:
    CRYPT_RandRegist(func);
    CRYPT_RandRegistEx(funcEx);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    BSL_SAL_Free(pub.key.rsaPub.n);
    BSL_SAL_Free(pub.key.rsaPub.e);
    return ret;
}

static bool RsaSelftestDecrypt(void *libCtx, const char *attrName, const uint8_t *cipher, const uint32_t cipherLen,
    const uint8_t *plain, const uint32_t plainLen)
{
    bool ret = false;
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    CRYPT_EAL_PkeyPrv prv = { 0 };

    uint8_t plainText[MAX_CIPHER_TEXT_LEN] = {0};
    uint32_t plainTextLen = sizeof(plainText);
    int32_t err = CRYPT_CMVP_ERR_ALGO_SELFTEST;
    CRYPT_MD_AlgId mdId = RSA_ENC_DEC_VECTOR.mdId;
    BSL_Param oaep[3] = {{CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        BSL_PARAM_END
    };

    // decrypt
    prvCtx = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_RSA, 0, attrName);
    GOTO_ERR_IF_TRUE(prvCtx == NULL, err);
    GOTO_ERR_IF_TRUE(GetPrvKey(RSA_ENC_DEC_VECTOR.n, RSA_ENC_DEC_VECTOR.d, &prv) != true, err);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPrv(prvCtx, &prv) != CRYPT_SUCCESS, err);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyCtrl(prvCtx, CRYPT_CTRL_SET_RSA_RSAES_OAEP, oaep, 0) != CRYPT_SUCCESS, err);
    GOTO_ERR_IF_TRUE(
        CRYPT_EAL_PkeyDecrypt(prvCtx, cipher, cipherLen, plainText, &plainTextLen) != CRYPT_SUCCESS, err);

    GOTO_ERR_IF_TRUE(plainTextLen != plainLen, err);
    GOTO_ERR_IF_TRUE(memcmp(plain, plainText, plainTextLen) != 0, err);
    ret = true;
ERR:
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    BSL_SAL_Free(prv.key.rsaPrv.n);
    BSL_SAL_Free(prv.key.rsaPrv.d);
    return ret;
}

static bool RsaSelftestEncryptDecrypt(void *libCtx, const char *attrName)
{
    bool ret = false;
    uint8_t *plain = NULL;
    uint32_t plainLen;
    uint8_t *cipher = NULL;
    uint32_t cipherLen;

    plain = CMVP_StringsToBins(RSA_ENC_DEC_VECTOR.msg, &plainLen);
    GOTO_ERR_IF_TRUE(plain == NULL, CRYPT_CMVP_COMMON_ERR);
    cipher = CMVP_StringsToBins(RSA_ENC_DEC_VECTOR.cipher, &cipherLen);
    GOTO_ERR_IF_TRUE(cipher == NULL, CRYPT_CMVP_COMMON_ERR);

    GOTO_ERR_IF_TRUE(
        RsaSelftestEncrypt(libCtx, attrName, plain, plainLen, cipher, cipherLen) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(
        RsaSelftestDecrypt(libCtx, attrName, cipher, cipherLen, plain, plainLen) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = true;
ERR:
    BSL_SAL_Free(plain);
    BSL_SAL_Free(cipher);
    return ret;
}

bool CRYPT_CMVP_SelftestProviderRsa(void *libCtx, const char *attrName)
{
    GOTO_ERR_IF_TRUE(RsaSelftestSign(libCtx, attrName, PKCSV15_PAD) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(RsaSelftestVerify(libCtx, attrName, PKCSV15_PAD) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(RsaSelftestSign(libCtx, attrName, PSS_PAD) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(RsaSelftestVerify(libCtx, attrName, PSS_PAD) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(RsaSelftestEncryptDecrypt(libCtx, attrName) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    return true;
ERR:
    return false;
}

bool CRYPT_CMVP_SelftestRsa(void)
{
    GOTO_ERR_IF_TRUE(RsaSelftestSign(NULL, NULL, PKCSV15_PAD) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(RsaSelftestVerify(NULL, NULL, PKCSV15_PAD) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(RsaSelftestSign(NULL, NULL, PSS_PAD) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(RsaSelftestVerify(NULL, NULL, PSS_PAD) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(RsaSelftestEncryptDecrypt(NULL, NULL) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    return true;
ERR:
    return false;
}

#endif /* HITLS_CRYPTO_CMVP_ISO19790 || HITLS_CRYPTO_CMVP_FIPS */
