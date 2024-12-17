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
    {{3, "\125\35\43", BSL_OID_GLOBAL}, "AuthorityKeyIdentifier", BSL_CID_CE_AUTHORITYKEYIDENTIFIER},
    {{3, "\125\35\16", BSL_OID_GLOBAL}, "SubjectKeyIdentifier", BSL_CID_CE_SUBJECTKEYIDENTIFIER},
    {{3, "\125\35\17", BSL_OID_GLOBAL}, "KeyUsage", BSL_CID_CE_KEYUSAGE},
    {{3, "\125\35\21", BSL_OID_GLOBAL}, "SubjectAltName", BSL_CID_CE_SUBJECTALTNAME},
    {{3, "\125\35\23", BSL_OID_GLOBAL}, "BasicConstraints", BSL_CID_CE_BASICCONSTRAINTS},
    {{3, "\125\35\24", BSL_OID_GLOBAL}, "CrlNumber", BSL_CID_CE_CRLNUMBER},
    {{3, "\125\35\25", BSL_OID_GLOBAL}, "CrlReason", BSL_CID_CE_CRLREASON},
    {{3, "\125\35\30", BSL_OID_GLOBAL}, "InvalidityDate", BSL_CID_CE_INVALIDITYDATE},
    {{3, "\125\35\33", BSL_OID_GLOBAL}, "DeltaCrlIndicator", BSL_CID_CE_DELTACRLINDICATOR},
    {{3, "\125\35\34", BSL_OID_GLOBAL}, "IssuingDistributionPoint", BSL_CID_CE_ISSUINGDISTRIBUTIONPOINT},
    {{3, "\125\35\35", BSL_OID_GLOBAL}, "CertificateIssuer", BSL_CID_CE_CERTIFICATEISSUER},
    {{3, "\125\35\45", BSL_OID_GLOBAL}, "ExtendedKeyUsage", BSL_CID_CE_EXTKEYUSAGE},
    {{3, "\125\35\56", BSL_OID_GLOBAL}, "FreshestCRL", BSL_CID_CE_FRESHESTCRL},
    {{8, "\53\6\1\5\5\7\3\1", BSL_OID_GLOBAL}, "ServerAuth", BSL_CID_CE_SERVERAUTH},
    {{8, "\53\6\1\5\5\7\3\2", BSL_OID_GLOBAL}, "ClientAuth", BSL_CID_CE_CLIENTAUTH},
    {{8, "\53\6\1\5\5\7\3\3", BSL_OID_GLOBAL}, "CodeSigning", BSL_CID_CE_CODESIGNING},
    {{8, "\53\6\1\5\5\7\3\4", BSL_OID_GLOBAL}, "EmailProtection", BSL_CID_CE_EMAILPROTECTION},
    {{8, "\53\6\1\5\5\7\3\10", BSL_OID_GLOBAL}, "TimeStamping", BSL_CID_CE_TIMESTAMPING},
    {{8, "\53\6\1\5\5\7\3\11", BSL_OID_GLOBAL}, "OSCPSigning", BSL_CID_CE_OSCPSIGNING},
    {{9, "\52\206\110\206\367\15\1\1\10", BSL_OID_GLOBAL}, "MGF1", BSL_CID_MGF1},
    {{7, "\52\206\110\316\75\2\1", BSL_OID_GLOBAL}, "EC-PUBLICKEY", BSL_CID_EC_PUBLICKEY}, // ecc subkey
    {{3, "\125\4\3", BSL_OID_GLOBAL}, "CN", BSL_CID_COMMONNAME},
    {{3, "\125\4\4", BSL_OID_GLOBAL}, "SN", BSL_CID_SURNAME},
    {{3, "\125\4\5", BSL_OID_GLOBAL}, "serialNumber", BSL_CID_SERIALNUMBER},
    {{3, "\125\4\6", BSL_OID_GLOBAL}, "C", BSL_CID_COUNTRYNAME},
    {{3, "\125\4\7", BSL_OID_GLOBAL}, "L", BSL_CID_LOCALITYNAME},
    {{3, "\125\4\10", BSL_OID_GLOBAL}, "ST", BSL_CID_STATEORPROVINCENAME},
    {{3, "\125\4\11", BSL_OID_GLOBAL}, "STREET", BSL_CID_STREETADDRESS},
    {{3, "\125\4\12", BSL_OID_GLOBAL}, "O", BSL_CID_ORGANIZATIONNAME},
    {{3, "\125\4\13", BSL_OID_GLOBAL}, "OU", BSL_CID_ORGANIZATIONUNITNAME},
    {{3, "\125\4\14", BSL_OID_GLOBAL}, "title", BSL_CID_TITLE},
    {{3, "\125\4\52", BSL_OID_GLOBAL}, "GN", BSL_CID_GIVENNAME},
    {{3, "\125\4\53", BSL_OID_GLOBAL}, "initials", BSL_CID_INITIALS},
    {{3, "\125\4\54", BSL_OID_GLOBAL}, "generationQualifier", BSL_CID_GENERATIONQUALIFIER},
    {{3, "\125\4\56", BSL_OID_GLOBAL}, "dnQualifier", BSL_CID_DNQUALIFIER},
    {{3, "\125\4\101", BSL_OID_GLOBAL}, "pseudonym", BSL_CID_PSEUDONYM},
    {{10, "\11\222\46\211\223\362\54\144\1\31", BSL_OID_GLOBAL}, "DC", BSL_CID_DOMAINCOMPONENT},
    {{10, "\11\222\46\211\223\362\54\144\1\1", BSL_OID_GLOBAL}, "UID", BSL_CID_USERID},
    {{9, "\52\206\110\206\367\15\1\11\1", BSL_OID_GLOBAL}, "emailAddress", BSL_CID_EMAILADDRESS},

    {{9, "\52\206\110\206\367\15\1\11\16", BSL_OID_GLOBAL}, "Requested Extensions", BSL_CID_REQ_EXTENSION},

    {{9, "\52\206\110\206\367\15\1\7\1", BSL_OID_GLOBAL}, "data", BSL_CID_PKCS7_SIMPLEDATA},
    {{9, "\52\206\110\206\367\15\1\7\6", BSL_OID_GLOBAL}, "encryptedData", BSL_CID_PKCS7_ENCRYPTEDDATA},

    {{9, "\52\206\110\206\367\15\1\11\24", BSL_OID_GLOBAL}, "friendlyName", BSL_CID_FRIENDLYNAME},
    {{9, "\52\206\110\206\367\15\1\11\25", BSL_OID_GLOBAL}, "localKeyId", BSL_CID_LOCALKEYID},
    {{10, "\52\206\110\206\367\15\1\11\26\1", BSL_OID_GLOBAL}, "x509Certificate", BSL_CID_X509CERTIFICATE},

    {{11, "\52\206\110\206\367\15\1\14\12\1\1", BSL_OID_GLOBAL}, "keyBag", BSL_CID_KEYBAG},
    {{11, "\52\206\110\206\367\15\1\14\12\1\2", BSL_OID_GLOBAL}, "pkcs8shroudedkeyBag", BSL_CID_PKCS8SHROUDEDKEYBAG},
    {{11, "\52\206\110\206\367\15\1\14\12\1\3", BSL_OID_GLOBAL}, "certBag", BSL_CID_CERTBAG},
    {{11, "\52\206\110\206\367\15\1\14\12\1\4", BSL_OID_GLOBAL}, "crlBag", BSL_CID_CRLBAG},
    {{11, "\52\206\110\206\367\15\1\14\12\1\5", BSL_OID_GLOBAL}, "secretBag", BSL_CID_SECRETBAG},
    {{11, "\52\206\110\206\367\15\1\14\12\1\6", BSL_OID_GLOBAL}, "safeContent", BSL_CID_SAFECONTENTSBAG},
};

typedef struct {
    BslCid signId;
    BslCid asymId;
    BslCid hashId;
} BslSignIdMap;

static BslSignIdMap g_signIdMap[] = {
    {BSL_CID_MD5WITHRSA, BSL_CID_RSA, BSL_CID_MD5},
    {BSL_CID_SHA1WITHRSA, BSL_CID_RSA, BSL_CID_SHA1},
    {BSL_CID_SHA224WITHRSAENCRYPTION, BSL_CID_RSA, BSL_CID_SHA224},
    {BSL_CID_SHA256WITHRSAENCRYPTION, BSL_CID_RSA, BSL_CID_SHA256},
    {BSL_CID_SHA384WITHRSAENCRYPTION, BSL_CID_RSA, BSL_CID_SHA384},
    {BSL_CID_SHA512WITHRSAENCRYPTION, BSL_CID_RSA, BSL_CID_SHA512},
    {BSL_CID_SM3WITHRSAENCRYPTION, BSL_CID_RSA, BSL_CID_SM3},
    {BSL_CID_ECDSAWITHSHA1, BSL_CID_ECDSA, BSL_CID_SHA1},
    {BSL_CID_ECDSAWITHSHA224, BSL_CID_ECDSA, BSL_CID_SHA224},
    {BSL_CID_ECDSAWITHSHA256, BSL_CID_ECDSA, BSL_CID_SHA256},
    {BSL_CID_ECDSAWITHSHA384, BSL_CID_ECDSA, BSL_CID_SHA384},
    {BSL_CID_ECDSAWITHSHA512, BSL_CID_ECDSA, BSL_CID_SHA512},
    {BSL_CID_SM2DSAWITHSM3, BSL_CID_SM2, BSL_CID_SM3},
};

/**
 * RFC 5280: A.1. Explicitly Tagged Module, 1988 Syntax
 * -- Upper Bounds
*/

static const BslAsn1StrInfo g_asn1StrTab[] = {
    {BSL_CID_COMMONNAME, 1, 64}, // ub-common-name INTEGER ::= 64
    {BSL_CID_SURNAME, 1, 40}, // ub-surname-length INTEGER ::= 40
    {BSL_CID_SERIALNUMBER, 1, 64}, // ub-serial-number INTEGER ::= 64
    {BSL_CID_COUNTRYNAME, 2, 2}, // ub-country-name-alpha-length INTEGER ::= 2
    {BSL_CID_LOCALITYNAME, 1, 128}, // ub-locality-name INTEGER ::= 128
    {BSL_CID_STATEORPROVINCENAME, 1, 128}, // ub-state-name INTEGER ::= 128
    {BSL_CID_STREETADDRESS, 1, -1}, // no limited
    {BSL_CID_ORGANIZATIONNAME, 1, 64}, // ub-organization-name INTEGER ::= 64
    {BSL_CID_ORGANIZATIONUNITNAME, 1, 64}, // ub-organizational-unit-name INTEGER ::= 64
    {BSL_CID_TITLE, 1, 64}, // ub-title INTEGER ::= 64
    {BSL_CID_GIVENNAME, 1, 32768}, // ub-name INTEGER ::= 32768
    {BSL_CID_INITIALS, 1, 32768}, // ub-name INTEGER ::= 32768
    {BSL_CID_GENERATIONQUALIFIER, 1, 32768}, // ub-name INTEGER ::= 32768
    {BSL_CID_DNQUALIFIER, 1, -1}, // no limited
    {BSL_CID_PSEUDONYM, 1, 128}, // ub-pseudonym INTEGER ::= 128
    {BSL_CID_DOMAINCOMPONENT, 1, -1, }, // no limited
    {BSL_CID_USERID, 1, 256}, // RFC1274
};

BslCid BSL_OBJ_GetSignIdFromHashAndAsymId(BslCid asymAlg, BslCid hashAlg)
{
    if (asymAlg == BSL_CID_UNKNOWN || hashAlg == BSL_CID_UNKNOWN) {
        return BSL_CID_UNKNOWN;
    }
    for (uint32_t i = 0; i < sizeof(g_signIdMap) / sizeof(g_signIdMap[0]); i++) {
        if (g_signIdMap[i].asymId == asymAlg && g_signIdMap[i].hashId == hashAlg) {
            return g_signIdMap[i].signId;
        }
    }
    return BSL_CID_UNKNOWN;
}

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
        if (g_oidTable[i].strOid.octetLen == oid->octetLen) {
            if (memcmp(g_oidTable[i].strOid.octs, oid->octs, oid->octetLen) == 0) {
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
        if (g_oidTable[i].strOid.octetLen == oid->octetLen) {
            if (memcmp(g_oidTable[i].strOid.octs, oid->octs, oid->octetLen) == 0) {
                return g_oidTable[i].oidName;
            }
        }
    }
    return NULL;
}

const BslAsn1StrInfo *BSL_OBJ_GetAsn1StrFromCid(BslCid cid)
{
    for (size_t i = 0; i < sizeof(g_asn1StrTab) / sizeof(g_asn1StrTab[0]); i++) {
        if (cid == g_asn1StrTab[i].cid) {
            return &g_asn1StrTab[i];
        }
    }

    return NULL;
}
#endif
