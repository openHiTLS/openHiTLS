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
#include "crypt_utils.h"
#include "bsl_sal.h"

typedef struct {
    CRYPT_PKEY_ParaId paraId;
    const char *p;
    const char *q;
    const char *g;
    const char *xa;
    const char *ya;
    const char *xb;
    const char *yb;
    const char *z;
} CMVP_DH_VECTOR;

// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/key-management
static const CMVP_DH_VECTOR DH_VECTOR_MODP2048 = {
    .paraId = CRYPT_DH_RFC3526_2048,
    .p = "f528aa2762df76d7802fea087005d76feb69b7afd9e7fb363715a1b44f09dbda5d06a6"
        "3e3d512abe9c6810abba2bfd48cf554513712df25f786265a75f4e1dacaacbbe9e528a"
        "6346a8bf38015ecbc523d4e78d738b8852bcd66600dc434286c78f6ccae992568b258b"
        "b0d3b503e37e7a956ec1616978c1e7989229e39914ea7c1bea3902e669dfc62368da13"
        "7448350c1def54bf3ee2142c065601dfae6bca07e93cc463393cbc483b2c7272553788"
        "2ed5b96074f519fc738f5033b87b5edca0ec4a34dc0f84d2fa2c365f691a8fc7dc64bc"
        "0839a5813fef9af385c68e952af566f79b0802be9900cf0838032ed249afea05572154"
        "0c8961e6300ad5dec651c7",
    .q = "fa472bf5133f45b4c7ab14078e1281b487fc4fde1422ba4cafa2a64ea1aad989",
    .g = "085c0a0512c241b583d41703edfbfea2a3e863deac68855097707967e097186ef89d05"
        "c65227f56b12de6123bac86c3c13d680994bffaf24b2a1ed7f01c108b06593f22f74b4"
        "af222b46e5fb89482fbd96f5451c9f45393136ec037aa81a81245459ec018024518394"
        "f4d936596dc53c3d8a9f732903719796c045b62fadea9dd1b2fabec1560ddb3b780d96"
        "46ad0dd3168c07cc994f79ee804cae07573912511de050d05a0d58b819ec41e7c1205d"
        "c7199fc65a6a1a4ffcb4df38d9b6757269003401d84c732385a55174f27d4b493cb710"
        "980c3af98be7bcff9467e81792f2d2f9a2f8d5d0ddc9a229790192a194da5b2032f2f0"
        "cc23ffbcb2cc166f2128ee",
    .xa = "e62d8fdb14fcdc8e4b0c254216eb584a8e79115a294119806ac660cc9d0e3222",
    .ya = "815e1c8e64be6786b6c2194506b661199a56c807c6340a83697d3bc75304fbeb91bb15"
        "ac7981babba260a653e666b0da8012042a088547f0fbd1ef56d1d1f65ed809ca854513"
        "9f57d3ebda3e0f13e7ef19bded4a8dfa204f2457a3d392839dd70bec538a29d7887470"
        "9f905ec28740be157696aa862b57ab51ef20033601ff83ba3fb0e80255674e0e6e7269"
        "cd85ca10379d418b737d3cdeb5f31fb06f4a141145936a9eec0551b4ba59c59d2b3edd"
        "c19ea18978279cf11f21a65a9d2a104cfe6af93fa8a1ccd18b03017a8ab31943993192"
        "f794d87bbc273ef9160af954480783cfb6a37ba085503ba258169a8daba71d4c52de7c"
        "4e65472223c202ad277e93",
    .xb = "561c948be9d0d968cdfc6d27cbfe52cda342f544f56d57f118866326f76e1f70",
    .yb = "3c24973b3296269759ce38e2e525c0095d4b5c34be5d13b45b222b8e489c27fb4442f3"
        "2cc764665e28a06655c71fb37fd875a921d179551a1e4f2a9054a76cae2a61d3cbec55"
        "c3be19853a5409d9ff914b93bc78b8aa1525b908f32419a88d7726ead76a3f8895d630"
        "71a9b0a63fe4728d19518d1d08088141b8269f0b0cd77112d476af9efcc7f590af8fc1"
        "f9dc5e4c00cd5dfa64a33b2df4db9d8594d87489bea6f6f37958bfb598e5692b81bf11"
        "6b60227b6252a6438f049c5c449bab027740f8551bf1ffe25084f231ff646388d009ba"
        "22193262029ba19af2643dd679f283212a2d26ad917efe9642c748fceb33fb0a6c132f"
        "378dada2cccede086d8a31",
    .z = "ec2309a7d238aeb06714c27c1bbbb1b1c5aa3cdddd76a419b1f3704dd3437cd1f2c884"
        "3f350d67872ee325973f4e5ace7d406be5de75d9a9120af67e32f0291e77e7a3976249"
        "29d63dc0c42ef8f442ce89a39b192fee386ce68301c4b828ea9189798346b60f615dd9"
        "639105ffea6ec61ee5e4a7d68ce72bbf1281d6864e30181ce419952a3ef83a9ad7b26f"
        "c7292ad745bfb543e5c2ea310a4159e9d660279d12c1e03850e837c01c542a0f59ad61"
        "d0731005e8009a3d8406691abb22f5f2e96ae345783c403e59b9e948addbea8ac7d770"
        "821044e03f15ae6fc367ddc85ba62a26b4d94d7705f5ecad8aa21b619d0e09f124bee8"
        "658a2187f7029107105dbf"
};

// Test vectors sourced from NIST ACVP-Server.
static const CMVP_DH_VECTOR DH_VECTOR_FFDHE2048 = {
    .paraId = CRYPT_DH_RFC7919_2048,
    .p = NULL,
    .q = NULL,
    .g = NULL,
    .xa = "39983F0CD77A92B44E304AF18C811DB1DB2B820055F1A6CC8B78BFFFA57EB08299664B"
          "2CF76C3D5564FEC48C2F2F56AA63ACED5D11AB0B3390C008A94BD4351416DC978F5750"
          "410A2B618105EE9847DC9AB12AB39C971522EF97919E57C4DE706614FE20037738F871"
          "7895D5BC41458C437DA33F89745D6D742CC29632C0AF0A36CE0B99E0231D4C27833E71"
          "60F2687801462D5AA038B89A802B5E1ADF42A1D97C142D5851103E9034AE33B7916397"
          "D23BA16B9FF481FC1FD45FE35AA85E27B0E6A58A60A8E37D2A4D237793C4FA4E1E04ED"
          "F6090A4331237C9F8C2C19076367762D92491024A5F6B3BA510496154E05B43CE1A722"
          "9F793ABD2458095B3D9C78",
    .ya = "5FA0CB4D5A976B11442FFDA4569FFF10058E41988C78D0AB6E39B2E226EEFB7C13B9FD"
          "65720940118134762CD1ADE1EA83AF64548D8C8BFFA564C8747860FF816AE9C6F13797"
          "9FA7C2A4D3E12A3DE68986B43F14CC808E61FAEBAF702FF523795459CFCD19F83563F2"
          "5EFC0E57277512FAA8FA23CEF3C8F1D517ABED113FECEE21D926D96BA52A716B5FCDF1"
          "87D1ACD999A9CFA951311A042C55C693B20B0DDD98C2F2BBEF67E77FD9E18F0D52045E"
          "0B424ED3ECBBD2F34E008FD5C7B482B99CED2A7963DFCA54C5EF9E1FB56F4450B7312C"
          "F389D66A696479A6BFEE031D2ECED27969A4061E73331C63B6F21BD7D6E8358FF052F8"
          "71DE595DFD57752016D1CA",
    .xb = "78502F2AF8969B51D50D2756BAA5EF936FA735B2B2F8423E00D347FF6FB078F14BFA8B"
          "2A01A4CBF700C4861A7C65C7EFA026B6AAA7A60B944B09364D29AC3A9C10F6066AA0BB"
          "0115BA15E3934A6C9E981B5732E03A32FC23B3B320089F4EA6CFB31C6C7107E99C3063"
          "751238D21352BE40B602F94131D9C2D26E3444437D58ED0793D48ACC50749235F26B66"
          "837923750E5801F91ED3584A585A0FB213142312A438BE35A309D87009C30F40D49D2E"
          "D554F9D6BCBE84F54AB6382E7425FCADAED9D11909FA4624647B963605BC68896A34DA"
          "5C7F20447AD19C3381F87F40DC63969855A50E92D4448E432189697F7CAB4191D2B175"
          "6BB01FF62D4CA1661F6A33",
    .yb = "8CDD3810AA88A5410A5E416A68E9CD31A4542EEC0073A67D12300D3DC1EE5890AFE2DA"
          "CA654BFC29C63E1D011C7A52E3DE8D89A3771F43F6921521BB137D25459C90E46F090B"
          "FD53B58901109A28F587B96A35828C3464ACF6F80D9646494CF4389FD82BFE4E7AE2BB"
          "E5CA2694D7967F56A0E92D43E8C119BD81B7A50516BFA8B39BBEA538AE56556808F4B5"
          "C3BAD84A76A5EB373D596DBEF75AB90A49C902615C7386334B70BAE9AC0C4E953DB03B"
          "883B64E7E3C3FDD547C6BC3C004D032A57BA40E06DCB0E87016DDADED991FF34FD6ECA"
          "06635041DD98C0C4C1DEF942C751DB3F5218BC7C2F6039AF2323F473D3775ED27936FD"
          "2E209541C9FAEAE2A75874",
    .z =  "024E9786943F8AA48E0FC7B2862D620A6DDA720F7CEFB53A38D8DEDC8D8E29737BA62A"
          "2E4D04B7E64B2B23396497FBDE5FE803437199C1703C6DA3ED9867FCB358EFD5B98B8B"
          "077E608F39DFBF574A89AA5521F78856E04D05E02B525928C437DF2E2AD5D45B0E6E3C"
          "5D656CE2434D4D8BB4DCD11496C30615EB1970CA3DE40723518D79E8ED1A07BE59C486"
          "134E5075367A74CF1F9DCBFB85BA36E643D4915C481B3129BD6988CB2E7BE441DA257C"
          "924C34B431CE048F8F7BC21B601F51D1EA009C77D3E10F3A59196ED40EE2D80699970F"
          "76EEC65142617CF427F1386566FDCE92FBA5FE734071B504EED601797589BF7C7F9EAD"
          "508A7B5B4915DD477009E1",
};

static bool GetPara(const CMVP_DH_VECTOR *vector, CRYPT_EAL_PkeyPara *para)
{
    para->id = CRYPT_PKEY_DH;
    para->para.dhPara.p = CMVP_StringsToBins(vector->p, &(para->para.dhPara.pLen));
    GOTO_ERR_IF_TRUE(para->para.dhPara.p == NULL, CRYPT_CMVP_COMMON_ERR);
    para->para.dhPara.q = CMVP_StringsToBins(vector->q, &(para->para.dhPara.qLen));
    GOTO_ERR_IF_TRUE(para->para.dhPara.q == NULL, CRYPT_CMVP_COMMON_ERR);
    para->para.dhPara.g = CMVP_StringsToBins(vector->g, &(para->para.dhPara.gLen));
    GOTO_ERR_IF_TRUE(para->para.dhPara.g == NULL, CRYPT_CMVP_COMMON_ERR);
    return true;
ERR:
    return false;
}

static bool GetKey(const CMVP_DH_VECTOR *vector, CRYPT_EAL_PkeyPrv *prv1, CRYPT_EAL_PkeyPub *pub1,
    CRYPT_EAL_PkeyPrv *prv2, CRYPT_EAL_PkeyPub *pub2)
{
    prv1->id = CRYPT_PKEY_DH;
    prv1->key.dhPrv.data = CMVP_StringsToBins(vector->xa, &(prv1->key.dhPrv.len));
    GOTO_ERR_IF_TRUE(prv1->key.dhPrv.data == NULL, CRYPT_CMVP_COMMON_ERR);
    pub1->id = CRYPT_PKEY_DH;
    pub1->key.dhPub.data = CMVP_StringsToBins(vector->ya, &(pub1->key.dhPub.len));
    GOTO_ERR_IF_TRUE(pub1->key.dhPub.data == NULL, CRYPT_CMVP_COMMON_ERR);
    prv2->id = CRYPT_PKEY_DH;
    prv2->key.dhPrv.data = CMVP_StringsToBins(vector->xb, &(prv2->key.dhPrv.len));
    GOTO_ERR_IF_TRUE(prv2->key.dhPrv.data == NULL, CRYPT_CMVP_COMMON_ERR);
    pub2->id = CRYPT_PKEY_DH;
    pub2->key.dhPub.data = CMVP_StringsToBins(vector->yb, &(pub2->key.dhPub.len));
    GOTO_ERR_IF_TRUE(pub2->key.dhPub.data == NULL, CRYPT_CMVP_COMMON_ERR);
    return true;
ERR:
    return false;
}

static bool ComputeShareKey(const CMVP_DH_VECTOR *vector, CRYPT_EAL_PkeyCtx *prv, CRYPT_EAL_PkeyCtx *pub)
{
    bool ret = false;
    uint8_t *expShare = NULL;
    uint8_t *share = NULL;
    uint32_t expShareLen;
    uint32_t shareLen;

    expShare = CMVP_StringsToBins(vector->z, &expShareLen);
    GOTO_ERR_IF_TRUE(expShare == NULL, CRYPT_CMVP_COMMON_ERR);
    shareLen = expShareLen;
    share = BSL_SAL_Malloc(shareLen);
    GOTO_ERR_IF_TRUE(share == NULL, CRYPT_MEM_ALLOC_FAIL);

    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyComputeShareKey(prv, pub, share, &shareLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(shareLen != expShareLen, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(memcmp(share, expShare, expShareLen) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret = true;
ERR:
    BSL_SAL_Free(expShare);
    BSL_SAL_Free(share);
    return ret;
}

static void FreeData(CRYPT_EAL_PkeyPara para, CRYPT_EAL_PkeyPrv prv1, CRYPT_EAL_PkeyPub pub1, CRYPT_EAL_PkeyPrv prv2,
    CRYPT_EAL_PkeyPub pub2)
{
    BSL_SAL_Free(para.para.dhPara.p);
    BSL_SAL_Free(para.para.dhPara.q);
    BSL_SAL_Free(para.para.dhPara.g);
    BSL_SAL_Free(prv1.key.dhPrv.data);
    BSL_SAL_Free(pub1.key.dhPub.data);
    BSL_SAL_Free(prv2.key.dhPrv.data);
    BSL_SAL_Free(pub2.key.dhPub.data);
}

static bool CRYPT_CMVP_SelftestDhInternal(const CMVP_DH_VECTOR *vector, void *libCtx, const char *attrName)
{
    bool ret = false;
    CRYPT_EAL_PkeyPara para;
    para.para.dhPara.p = NULL;
    para.para.dhPara.q = NULL;
    para.para.dhPara.g = NULL;
    CRYPT_EAL_PkeyPrv prv1 = {0};
    prv1.key.dhPrv.data = NULL;
    CRYPT_EAL_PkeyPub pub1;
    pub1.key.dhPub.data = NULL;
    CRYPT_EAL_PkeyPrv prv2 = {0};
    prv2.key.dhPrv.data = NULL;
    CRYPT_EAL_PkeyPub pub2;
    pub2.key.dhPub.data = NULL;
    CRYPT_EAL_PkeyCtx *pkeyPrv = NULL;
    CRYPT_EAL_PkeyCtx *pkeyPub = NULL;

    if (vector->paraId == CRYPT_DH_RFC3526_2048) {
        GOTO_ERR_IF_TRUE(GetPara(vector, &para) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }
    GOTO_ERR_IF_TRUE(GetKey(vector, &prv1, &pub1, &prv2, &pub2) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    pkeyPrv = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_DH, 0, attrName);
    pkeyPub = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_DH, 0, attrName);
    GOTO_ERR_IF_TRUE(pkeyPrv == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(pkeyPub == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    if (vector->paraId == CRYPT_DH_RFC3526_2048) {
        GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPara(pkeyPrv, &para) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    } else {
        GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetParaById(pkeyPrv, vector->paraId) != CRYPT_SUCCESS,
            CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPrv(pkeyPrv, &prv1) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPub(pkeyPub, &pub2) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(ComputeShareKey(vector, pkeyPrv, pkeyPub) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPrv(pkeyPrv, &prv2) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPub(pkeyPub, &pub1) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(ComputeShareKey(vector, pkeyPrv, pkeyPub) != true, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = true;
ERR:
    FreeData(para, prv1, pub1, prv2, pub2);
    CRYPT_EAL_PkeyFreeCtx(pkeyPrv);
    CRYPT_EAL_PkeyFreeCtx(pkeyPub);
    return ret;
}

bool CRYPT_CMVP_SelftestDh(void)
{
    return CRYPT_CMVP_SelftestDhInternal(&DH_VECTOR_MODP2048, NULL, NULL) &&
        CRYPT_CMVP_SelftestDhInternal(&DH_VECTOR_FFDHE2048, NULL, NULL);
}

bool CRYPT_CMVP_SelftestProviderDh(void *libCtx, const char *attrName)
{
    return CRYPT_CMVP_SelftestDhInternal(&DH_VECTOR_MODP2048, libCtx, attrName) &&
        CRYPT_CMVP_SelftestDhInternal(&DH_VECTOR_FFDHE2048, libCtx, attrName);
}

#endif /* HITLS_CRYPTO_CMVP_ISO19790 || HITLS_CRYPTO_CMVP_FIPS */
