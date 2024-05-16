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
#ifdef HITLS_BSL_OBJ
#include <stddef.h>
#include "bsl_obj.h"
#include "bsl_obj_internal.h"
#include "securec.h"

BslOidInfo g_oidTable[] = {
    {{9, "\140\206\110\1\145\3\4\1\2", BSL_OID_GLOBAL}, "AES128-CBC", BSL_CID_AES128_CBC},
    {{9, "\140\206\110\1\145\3\4\1\26", BSL_OID_GLOBAL}, "AES192-CBC", BSL_CID_AES192_CBC},
    {{9, "\140\206\110\1\145\3\4\1\52", BSL_OID_GLOBAL}, "AES256-CBC", BSL_CID_AES256_CBC},
    {{8, "\52\201\34\317\125\1\150\2", BSL_OID_GLOBAL}, "SM4-CBC", BSL_CID_SM4_CBC},
    {{9, "\52\206\110\206\367\15\1\1\1", BSL_OID_GLOBAL}, "RSAENCRYPTION", BSL_CID_RSA}, // rsa subkey
    {{9, "\52\206\110\206\367\15\1\1\12", BSL_OID_GLOBAL}, "RSASSAPSS", BSL_CID_RSASSAPSS},
    {{9, "\52\206\110\206\367\15\1\1\4", BSL_OID_GLOBAL}, "MD5WITHRSA", BSL_CID_MD5WITHRSA},
    {{9, "\52\206\110\206\367\15\1\1\5", BSL_OID_GLOBAL}, "SHA1WITHRSA", BSL_CID_SHA1WITHRSA},
    {{9, "\52\206\110\206\367\15\1\1\16", BSL_OID_GLOBAL}, "SHA224WITHRSA", BSL_CID_SHA224WITHRSAENCRYPTION},
    {{9, "\52\206\110\206\367\15\1\1\13", BSL_OID_GLOBAL}, "SHA256WITHRSA", BSL_CID_SHA256WITHRSAENCRYPTION},
    {{9, "\52\206\110\206\367\15\1\1\14", BSL_OID_GLOBAL}, "SHA384WITHRSA", BSL_CID_SHA384WITHRSAENCRYPTION},
    {{9, "\52\206\110\206\367\15\1\1\15", BSL_OID_GLOBAL}, "SHA512WITHRSA", BSL_CID_SHA512WITHRSAENCRYPTION},
    {{8, "\52\201\34\317\125\1\203\170", BSL_OID_GLOBAL}, "SM3WITHRSA", BSL_CID_SM3WITHRSAENCRYPTION},
    {{7, "\52\206\110\316\70\4\1", BSL_OID_GLOBAL}, "DSAENCRYPTION", BSL_CID_DSA}, // dsa subkey
    {{7, "\52\206\110\316\70\4\3", BSL_OID_GLOBAL}, "DSAWITHSHA1", BSL_CID_DSAWITHSHA1},
    {{9, "\140\206\110\1\145\3\4\3\1", BSL_OID_GLOBAL}, "DSAWITHSHA224", BSL_CID_DSAWITHSHA224},
    {{9, "\140\206\110\1\145\3\4\3\2", BSL_OID_GLOBAL}, "DSAWITHSHA256", BSL_CID_DSAWITHSHA256},
    {{9, "\140\206\110\1\145\3\4\3\3", BSL_OID_GLOBAL}, "DSAWITHSHA384", BSL_CID_DSAWITHSHA384},
    {{9, "\140\206\110\1\145\3\4\3\4", BSL_OID_GLOBAL}, "DSAWITHSHA512", BSL_CID_DSAWITHSHA512},
    {{7, "\52\206\110\316\75\4\1", BSL_OID_GLOBAL}, "ECDSAWITHSHA1", BSL_CID_ECDSAWITHSHA1},
    {{8, "\52\206\110\316\75\4\3\1", BSL_OID_GLOBAL}, "ECDSAWITHSHA224", BSL_CID_ECDSAWITHSHA224},
    {{8, "\52\206\110\316\75\4\3\2", BSL_OID_GLOBAL}, "ECDSAWITHSHA256", BSL_CID_ECDSAWITHSHA256},
    {{8, "\52\206\110\316\75\4\3\3", BSL_OID_GLOBAL}, "ECDSAWITHSHA384", BSL_CID_ECDSAWITHSHA384},
    {{8, "\52\206\110\316\75\4\3\4", BSL_OID_GLOBAL}, "ECDSAWITHSHA512", BSL_CID_ECDSAWITHSHA512},
    {{8, "\52\201\34\317\125\1\203\165", BSL_OID_GLOBAL}, "SM2DSAWITHSM3", BSL_CID_SM2DSAWITHSM3},
    {{8, "\52\201\34\317\125\1\203\166", BSL_OID_GLOBAL}, "SM2DSAWITHSHA1", BSL_CID_SM2DSAWITHSHA1},
    {{8, "\52\201\34\317\125\1\203\167", BSL_OID_GLOBAL}, "SM2DSAWITHSHA256", BSL_CID_SM2DSAWITHSHA256},
    {{8, "\52\206\110\206\367\15\2\5", BSL_OID_GLOBAL}, "MD5", BSL_CID_MD5},
    {{5, "\53\16\3\2\32", BSL_OID_GLOBAL}, "SHA1", BSL_CID_SHA1},
    {{9, "\140\206\110\1\145\3\4\2\4", BSL_OID_GLOBAL}, "SHA224", BSL_CID_SHA224},
    {{9, "\140\206\110\1\145\3\4\2\1", BSL_OID_GLOBAL}, "SHA256", BSL_CID_SHA256},
    {{9, "\140\206\110\1\145\3\4\2\2", BSL_OID_GLOBAL}, "SHA384", BSL_CID_SHA384},
    {{9, "\140\206\110\1\145\3\4\2\3", BSL_OID_GLOBAL}, "SHA512", BSL_CID_SHA512},
    {{9, "\140\206\110\1\145\3\4\2\7", BSL_OID_GLOBAL}, "SHA3-224", BSL_CID_SHA3_224},
    {{9, "\140\206\110\1\145\3\4\2\10", BSL_OID_GLOBAL}, "SHA3-256", BSL_CID_SHA3_256},
    {{9, "\140\206\110\1\145\3\4\2\11", BSL_OID_GLOBAL}, "SHA3-384", BSL_CID_SHA3_384},
    {{9, "\140\206\110\1\145\3\4\2\12", BSL_OID_GLOBAL}, "SHA3-512", BSL_CID_SHA3_512},
    {{9, "\140\206\110\1\145\3\4\2\13", BSL_OID_GLOBAL}, "SHAKE128", BSL_CID_SHAKE128},
    {{9, "\140\206\110\1\145\3\4\2\14", BSL_OID_GLOBAL}, "SHAKE256", BSL_CID_SHAKE256},
    {{8, "\52\201\34\317\125\1\203\21", BSL_OID_GLOBAL}, "SM3", BSL_CID_SM3},
    {{8, "\53\6\1\5\5\10\1\1", BSL_OID_GLOBAL}, "HMAC-MD5", BSL_CID_HMAC_MD5},
    {{8, "\52\206\110\206\367\15\2\7", BSL_OID_GLOBAL}, "HMAC-SHA1", BSL_CID_HMAC_SHA1},
    {{8, "\52\206\110\206\367\15\2\10", BSL_OID_GLOBAL}, "HMAC-SHA224", BSL_CID_HMAC_SHA224},
    {{8, "\52\206\110\206\367\15\2\11", BSL_OID_GLOBAL}, "HMAC-SHA256", BSL_CID_HMAC_SHA256},
    {{8, "\52\206\110\206\367\15\2\12", BSL_OID_GLOBAL}, "HMAC-SHA384", BSL_CID_HMAC_SHA384},
    {{8, "\52\206\110\206\367\15\2\13", BSL_OID_GLOBAL}, "HMAC-SHA512", BSL_CID_HMAC_SHA512},
    {{9, "\52\206\110\206\367\15\1\5\14", BSL_OID_GLOBAL}, "PBKDF2", BSL_CID_PBKDF2},
    {{9, "\52\206\110\206\367\15\1\5\15", BSL_OID_GLOBAL}, "PBES2", BSL_CID_PBES2},
    {{9, "\53\44\3\3\2\10\1\1\7", BSL_OID_GLOBAL}, "BRAINPOOLP256R1", BSL_CID_ECC_BRAINPOOLP256R1},
    {{9, "\53\44\3\3\2\10\1\1\13", BSL_OID_GLOBAL}, "BRAINPOOLP384R1", BSL_CID_ECC_BRAINPOOLP384R1},
    {{9, "\53\44\3\3\2\10\1\1\15", BSL_OID_GLOBAL}, "BRAINPOOLP512R1", BSL_CID_ECC_BRAINPOOLP512R1},
    {{5, "\53\201\4\0\42", BSL_OID_GLOBAL}, "SECP384R1", BSL_CID_SECP384R1},
    {{5, "\53\201\4\0\43", BSL_OID_GLOBAL}, "SECP521R1", BSL_CID_SECP521R1},
    {{8, "\52\206\110\316\75\3\1\7", BSL_OID_GLOBAL}, "PRIME256V1", BSL_CID_PRIME256V1},
    {{5, "\53\201\4\0\41", BSL_OID_GLOBAL}, "PRIME224", BSL_CID_NIST_PRIME224},
    {{8, "\52\201\34\317\125\1\202\55", BSL_OID_GLOBAL}, "SM2PRIME256", BSL_CID_SM2PRIME256},
    {{3, "\125\35\17", BSL_OID_GLOBAL}, "CE-KEYUSAGE", BSL_CID_CE_KEYUSAGE},
    {{3, "\125\35\23", BSL_OID_GLOBAL}, "CE-BASICCONSTRAINTS", BSL_CID_CE_BASICCONSTRAINTS},
    {{7, "\52\206\110\316\75\2\1", BSL_OID_GLOBAL}, "EC-PUBLICKEY", BSL_CID_EC_PUBLICKEY}, // ecc subkey
    {{3, "\125\4\3", BSL_OID_GLOBAL}, "CN", BSL_CID_COMMONNAME},
    {{3, "\125\4\7", BSL_OID_GLOBAL}, "L", BSL_CID_LOCALITYNAME},
    {{3, "\125\4\10", BSL_OID_GLOBAL}, "ST", BSL_CID_STATEORPROVINCENAME},
    {{3, "\125\4\12", BSL_OID_GLOBAL}, "O", BSL_CID_ORGANIZATIONNAME},
    {{3, "\125\4\13", BSL_OID_GLOBAL}, "OU", BSL_CID_ORGANIZATIONUNITNAME},
    {{3, "\125\4\6", BSL_OID_GLOBAL}, "C", BSL_CID_COUNTRYNAME},
    {{3, "\125\4\11", BSL_OID_GLOBAL}, "STREET", BSL_CID_STREETADDRESS},
    {{10, "\11\222\46\211\223\362\54\144\1\31", BSL_OID_GLOBAL}, "DC", BSL_CID_DOMAINCOMPONENT},
    {{10, "\11\222\46\211\223\362\54\144\1\1", BSL_OID_GLOBAL}, "UID", BSL_CID_USERID},
    {{9, "\52\206\110\206\367\15\1\11\1", BSL_OID_GLOBAL}, "emailAddress", BSL_CID_EMAILADDRESS},
};

uint32_t g_tableSize = (uint32_t)sizeof(g_oidTable)/sizeof(g_oidTable[0]);

static int32_t GetOidIndex(int32_t inputCid)
{
    int32_t left = 0;
    int32_t right = g_tableSize - 1;
    while (left <= right) {
        int32_t mid = (right - left) / 2 + left;
        int32_t cid = g_oidTable[mid].cid;
        if (cid == inputCid) {
            return mid;
        } else if (cid > inputCid) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }
    return -1;
}

BslCid BSL_OBJ_GetCIDFromOid(BslOidString *oid)
{
    if (oid == NULL || oid->octs == NULL) {
        return BSL_CID_UNKNOWN;
    }
    
    for (uint32_t i = 0; i < g_tableSize; i++) {
        if (g_oidTable[i].strOid.octedLen == oid->octedLen) {
            if (memcmp(g_oidTable[i].strOid.octs, oid->octs, oid->octedLen) == 0) {
                return g_oidTable[i].cid;
            }
        }
    }
    return BSL_CID_UNKNOWN;
}

BslOidString *BSL_OBJ_GetOidFromCID(BslCid inputCid)
{
    if (inputCid >= BSL_CID_MAX) {
        return NULL;
    }
    int32_t index = GetOidIndex(inputCid);
    if (index == -1) {
        return NULL;
    }
    return &g_oidTable[index].strOid;
}

const char *BSL_OBJ_GetOidNameFromOid(const BslOidString *oid)
{
    if (oid == NULL || oid->octs == NULL) {
        return NULL;
    }

    for (uint32_t i = 0; i < g_tableSize; i++) {
        if (g_oidTable[i].strOid.octedLen == oid->octedLen) {
            if (memcmp(g_oidTable[i].strOid.octs, oid->octs, oid->octedLen) == 0) {
                return g_oidTable[i].oidName;
            }
        }
    }
    return NULL;
}

#endif