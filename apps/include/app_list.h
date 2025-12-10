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

#ifndef HITLS_APP_LIST_H
#define HITLS_APP_LIST_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HITLS_APP_LIST_OPT_ALL_ALG = 2,
    HITLS_APP_LIST_OPT_DGST_ALG,
    HITLS_APP_LIST_OPT_CIPHER_ALG,
    HITLS_APP_LIST_OPT_ASYM_ALG,
    HITLS_APP_LIST_OPT_MAC_ALG,
    HITLS_APP_LIST_OPT_RAND_ALG,
    HITLS_APP_LIST_OPT_KDF_ALG,
    HITLS_APP_LIST_OPT_CURVES,
    HITLS_APP_LIST_OPT_MD_TO_MAC_ALG,
    HITLS_APP_LIST_OPT_PKCS12_MAC_ALG,
    HITLS_APP_LIST_OPT_PBE_ALG,
    HITLS_APP_LIST_OPT_KEY_MGMT_ALG,
    HITLS_APP_LIST_OPT_RSA_ALG
} HITLSListOptType;

int HITLS_ListMain(int argc, char *argv[]);

int32_t HITLS_APP_PrintStdoutUioInit(void);

void HITLS_APP_PrintStdoutUioUnInit(void);

void HITLS_APP_PrintCipherAlg(void);

void HITLS_APP_PrintMdToHmacAlg(void);

void HITLS_APP_PrintPkcs12MacIdAlg(void);

void HITLS_APP_PrintPbeAlg(void);

void HITLS_APP_PrintKeyMgmtIdAlg(void);

void HITLS_APP_PrintRsaIdAlg(void);

int32_t HITLS_APP_GetCidByName(const char *name, int32_t type);

const char *HITLS_APP_GetNameByCid(int32_t cid, int32_t type);

#ifdef __cplusplus
}
#endif
#endif // HITLS_APP_LIST_H
