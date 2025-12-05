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
#include <string.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_obj.h"
#include "bsl_obj_internal.h"
#include "bsl_err_internal.h"
#ifdef HITLS_BSL_OBJ_CUSTOM
#include "bsl_hash.h"

#define BSL_OBJ_HASH_BKT_SIZE 256u

BSL_HASH_Hash *g_oidHashTable = NULL;

static BSL_SAL_ThreadLockHandle g_oidHashRwLock = NULL;

BSL_SAL_DECLARE_THREAD_ONCE(g_oidHashInitOnce);
#endif // HITLS_BSL_OBJ_CUSTOM

#define BSL_OBJ_ARCS_X_MAX 2
#define BSL_OBJ_ARCS_Y_MAX 40
#define BSL_OBJ_ARCS_MAX (BSL_OBJ_ARCS_X_MAX * BSL_OBJ_ARCS_Y_MAX + BSL_OBJ_ARCS_Y_MAX - 1)

BslOidInfo g_oidTable[] = {
    {{9, "\140\206\110\1\145\3\4\1\1", BSL_OID_GLOBAL}, "aes-128-ecb", BSL_CID_AES128_ECB},
    {{9, "\140\206\110\1\145\3\4\1\2", BSL_OID_GLOBAL}, "aes-128-cbc", BSL_CID_AES128_CBC},
    {{9, "\140\206\110\1\145\3\4\1\3", BSL_OID_GLOBAL}, "aes-128-ofb", BSL_CID_AES128_OFB},
    {{9, "\140\206\110\1\145\3\4\1\4", BSL_OID_GLOBAL}, "aes-128-cfb", BSL_CID_AES128_CFB},
    {{9, "\140\206\110\1\145\3\4\1\25", BSL_OID_GLOBAL}, "aes-192-ecb", BSL_CID_AES192_ECB},
    {{9, "\140\206\110\1\145\3\4\1\26", BSL_OID_GLOBAL}, "aes-192-cbc", BSL_CID_AES192_CBC},
    {{9, "\140\206\110\1\145\3\4\1\27", BSL_OID_GLOBAL}, "aes-192-ofb", BSL_CID_AES192_OFB},
    {{9, "\140\206\110\1\145\3\4\1\30", BSL_OID_GLOBAL}, "aes-192-cfb", BSL_CID_AES192_CFB},
    {{9, "\140\206\110\1\145\3\4\1\51", BSL_OID_GLOBAL}, "aes-256-ecb", BSL_CID_AES256_ECB},
    {{9, "\140\206\110\1\145\3\4\1\52", BSL_OID_GLOBAL}, "aes-256-cbc", BSL_CID_AES256_CBC},
    {{9, "\140\206\110\1\145\3\4\1\53", BSL_OID_GLOBAL}, "aes-256-ofb", BSL_CID_AES256_OFB},
    {{9, "\140\206\110\1\145\3\4\1\54", BSL_OID_GLOBAL}, "aes-256-cfb", BSL_CID_AES256_CFB},
    {{9, "\52\206\110\206\367\15\1\1\1", BSL_OID_GLOBAL}, "RSAENCRYPTION", BSL_CID_RSA}, // rsa subkey
    {{7, "\52\206\110\316\70\4\1", BSL_OID_GLOBAL}, "DSAENCRYPTION", BSL_CID_DSA}, // dsa subkey
    {{8, "\52\206\110\206\367\15\2\5", BSL_OID_GLOBAL}, "MD5", BSL_CID_MD5},
    {{5, "\53\16\3\2\32", BSL_OID_GLOBAL}, "SHA1", BSL_CID_SHA1},
    {{9, "\140\206\110\1\145\3\4\2\4", BSL_OID_GLOBAL}, "SHA224", BSL_CID_SHA224},
    {{9, "\140\206\110\1\145\3\4\2\1", BSL_OID_GLOBAL}, "SHA256", BSL_CID_SHA256},
    {{9, "\140\206\110\1\145\3\4\2\2", BSL_OID_GLOBAL}, "SHA384", BSL_CID_SHA384},
    {{9, "\140\206\110\1\145\3\4\2\3", BSL_OID_GLOBAL}, "SHA512", BSL_CID_SHA512},
    {{8, "\53\6\1\5\5\10\1\1", BSL_OID_GLOBAL}, "HMAC-MD5", BSL_CID_HMAC_MD5},
    {{8, "\52\206\110\206\367\15\2\7", BSL_OID_GLOBAL}, "HMAC-SHA1", BSL_CID_HMAC_SHA1},
    {{8, "\52\206\110\206\367\15\2\10", BSL_OID_GLOBAL}, "HMAC-SHA224", BSL_CID_HMAC_SHA224},
    {{8, "\52\206\110\206\367\15\2\11", BSL_OID_GLOBAL}, "HMAC-SHA256", BSL_CID_HMAC_SHA256},
    {{8, "\52\206\110\206\367\15\2\12", BSL_OID_GLOBAL}, "HMAC-SHA384", BSL_CID_HMAC_SHA384},
    {{8, "\52\206\110\206\367\15\2\13", BSL_OID_GLOBAL}, "HMAC-SHA512", BSL_CID_HMAC_SHA512},
    {{9, "\52\206\110\206\367\15\1\1\4", BSL_OID_GLOBAL}, "MD5WITHRSA", BSL_CID_MD5WITHRSA},
    {{9, "\52\206\110\206\367\15\1\1\5", BSL_OID_GLOBAL}, "SHA1WITHRSA", BSL_CID_SHA1WITHRSA},
    {{7, "\52\206\110\316\70\4\3", BSL_OID_GLOBAL}, "DSAWITHSHA1", BSL_CID_DSAWITHSHA1},
    {{7, "\52\206\110\316\75\4\1", BSL_OID_GLOBAL}, "ECDSAWITHSHA1", BSL_CID_ECDSAWITHSHA1},
    {{8, "\52\206\110\316\75\4\3\1", BSL_OID_GLOBAL}, "ECDSAWITHSHA224", BSL_CID_ECDSAWITHSHA224},
    {{8, "\52\206\110\316\75\4\3\2", BSL_OID_GLOBAL}, "ECDSAWITHSHA256", BSL_CID_ECDSAWITHSHA256},
    {{8, "\52\206\110\316\75\4\3\3", BSL_OID_GLOBAL}, "ECDSAWITHSHA384", BSL_CID_ECDSAWITHSHA384},
    {{8, "\52\206\110\316\75\4\3\4", BSL_OID_GLOBAL}, "ECDSAWITHSHA512", BSL_CID_ECDSAWITHSHA512},
    {{9, "\52\206\110\206\367\15\1\1\13", BSL_OID_GLOBAL}, "SHA256WITHRSA", BSL_CID_SHA256WITHRSAENCRYPTION},
    {{9, "\52\206\110\206\367\15\1\1\14", BSL_OID_GLOBAL}, "SHA384WITHRSA", BSL_CID_SHA384WITHRSAENCRYPTION},
    {{9, "\52\206\110\206\367\15\1\1\15", BSL_OID_GLOBAL}, "SHA512WITHRSA", BSL_CID_SHA512WITHRSAENCRYPTION},
    {{8, "\52\206\110\316\75\3\1\7", BSL_OID_GLOBAL}, "PRIME256V1", BSL_CID_PRIME256V1},
    {{9, "\52\206\110\206\367\15\1\5\14", BSL_OID_GLOBAL}, "PBKDF2", BSL_CID_PBKDF2},
    {{9, "\52\206\110\206\367\15\1\5\15", BSL_OID_GLOBAL}, "PBES2", BSL_CID_PBES2},
    {{9, "\52\206\110\206\367\15\1\11\16", BSL_OID_GLOBAL}, "Requested Extensions", BSL_CID_EXTENSIONREQUEST},
    {{3, "\125\4\4", BSL_OID_GLOBAL}, "SN", BSL_CID_AT_SURNAME},
    {{3, "\125\4\52", BSL_OID_GLOBAL}, "GN", BSL_CID_AT_GIVENNAME},
    {{3, "\125\4\53", BSL_OID_GLOBAL}, "initials", BSL_CID_AT_INITIALS},
    {{3, "\125\4\54", BSL_OID_GLOBAL}, "generationQualifier", BSL_CID_AT_GENERATIONQUALIFIER},
    {{3, "\125\4\3", BSL_OID_GLOBAL}, "CN", BSL_CID_AT_COMMONNAME},
    {{3, "\125\4\7", BSL_OID_GLOBAL}, "L", BSL_CID_AT_LOCALITYNAME},
    {{3, "\125\4\10", BSL_OID_GLOBAL}, "ST", BSL_CID_AT_STATEORPROVINCENAME},
    {{3, "\125\4\12", BSL_OID_GLOBAL}, "O", BSL_CID_AT_ORGANIZATIONNAME},
    {{3, "\125\4\13", BSL_OID_GLOBAL}, "OU", BSL_CID_AT_ORGANIZATIONALUNITNAME},
    {{3, "\125\4\14", BSL_OID_GLOBAL}, "title", BSL_CID_AT_TITLE},
    {{3, "\125\4\56", BSL_OID_GLOBAL}, "dnQualifier", BSL_CID_AT_DNQUALIFIER},
    {{3, "\125\4\6", BSL_OID_GLOBAL}, "C", BSL_CID_AT_COUNTRYNAME},
    {{3, "\125\4\5", BSL_OID_GLOBAL}, "serialNumber", BSL_CID_AT_SERIALNUMBER},
    {{3, "\125\4\101", BSL_OID_GLOBAL}, "pseudonym", BSL_CID_AT_PSEUDONYM},
    {{10, "\11\222\46\211\223\362\54\144\1\31", BSL_OID_GLOBAL}, "DC", BSL_CID_DOMAINCOMPONENT},
    {{9, "\52\206\110\206\367\15\1\11\1", BSL_OID_GLOBAL}, "emailAddress", BSL_CID_EMAILADDRESS},
    {{3, "\125\35\43", BSL_OID_GLOBAL}, "AuthorityKeyIdentifier", BSL_CID_CE_AUTHORITYKEYIDENTIFIER},
    {{3, "\125\35\16", BSL_OID_GLOBAL}, "SubjectKeyIdentifier", BSL_CID_CE_SUBJECTKEYIDENTIFIER},
    {{3, "\125\35\17", BSL_OID_GLOBAL}, "KeyUsage", BSL_CID_CE_KEYUSAGE},
    {{3, "\125\35\21", BSL_OID_GLOBAL}, "SubjectAltName", BSL_CID_CE_SUBJECTALTNAME},
    {{3, "\125\35\23", BSL_OID_GLOBAL}, "BasicConstraints", BSL_CID_CE_BASICCONSTRAINTS},
    {{3, "\125\35\37", BSL_OID_GLOBAL}, "CRLDistributionPoints", BSL_CID_CE_CRLDISTRIBUTIONPOINTS},
    {{3, "\125\35\45", BSL_OID_GLOBAL}, "ExtendedKeyUsage", BSL_CID_CE_EXTKEYUSAGE},
    {{4, "\125\35\45\0", BSL_OID_GLOBAL}, "AnyExtendedKeyUsage", BSL_CID_ANYEXTENDEDKEYUSAGE},
    {{8, "\53\6\1\5\5\7\3\1", BSL_OID_GLOBAL}, "ServerAuth", BSL_CID_KP_SERVERAUTH},
    {{8, "\53\6\1\5\5\7\3\2", BSL_OID_GLOBAL}, "ClientAuth", BSL_CID_KP_CLIENTAUTH},
    {{8, "\53\6\1\5\5\7\3\3", BSL_OID_GLOBAL}, "CodeSigning", BSL_CID_KP_CODESIGNING},
    {{8, "\53\6\1\5\5\7\3\4", BSL_OID_GLOBAL}, "EmailProtection", BSL_CID_KP_EMAILPROTECTION},
    {{8, "\53\6\1\5\5\7\3\10", BSL_OID_GLOBAL}, "TimeStamping", BSL_CID_KP_TIMESTAMPING},
    {{8, "\53\6\1\5\5\7\3\11", BSL_OID_GLOBAL}, "OSCPSigning", BSL_CID_KP_OCSPSIGNING},
    {{3, "\125\35\56", BSL_OID_GLOBAL}, "FreshestCRL", BSL_CID_CE_FRESHESTCRL},
    {{3, "\125\35\24", BSL_OID_GLOBAL}, "CrlNumber", BSL_CID_CE_CRLNUMBER},
    {{3, "\125\35\34", BSL_OID_GLOBAL}, "IssuingDistributionPoint", BSL_CID_CE_ISSUINGDISTRIBUTIONPOINT},
    {{3, "\125\35\33", BSL_OID_GLOBAL}, "DeltaCrlIndicator", BSL_CID_CE_DELTACRLINDICATOR},
    {{3, "\125\35\25", BSL_OID_GLOBAL}, "CrlReason", BSL_CID_CE_CRLREASONS},
    {{3, "\125\35\35", BSL_OID_GLOBAL}, "CertificateIssuer", BSL_CID_CE_CERTIFICATEISSUER},
    {{3, "\125\35\30", BSL_OID_GLOBAL}, "InvalidityDate", BSL_CID_CE_INVALIDITYDATE},
    {{11, "\52\206\110\206\367\15\1\14\12\1\1", BSL_OID_GLOBAL}, "keyBag", BSL_CID_KEYBAG},
    {{11, "\52\206\110\206\367\15\1\14\12\1\2", BSL_OID_GLOBAL}, "pkcs8shroudedkeyBag", BSL_CID_PKCS8SHROUDEDKEYBAG},
    {{11, "\52\206\110\206\367\15\1\14\12\1\3", BSL_OID_GLOBAL}, "certBag", BSL_CID_CERTBAG},
    {{11, "\52\206\110\206\367\15\1\14\12\1\4", BSL_OID_GLOBAL}, "crlBag", BSL_CID_CRLBAG},
    {{11, "\52\206\110\206\367\15\1\14\12\1\5", BSL_OID_GLOBAL}, "secretBag", BSL_CID_SECRETBAG},
    {{11, "\52\206\110\206\367\15\1\14\12\1\6", BSL_OID_GLOBAL}, "safeContent", BSL_CID_SAFECONTENTSBAG},
    {{10, "\52\206\110\206\367\15\1\11\26\1", BSL_OID_GLOBAL}, "x509Certificate", BSL_CID_X509CERTIFICATE},
    {{9, "\52\206\110\206\367\15\1\11\24", BSL_OID_GLOBAL}, "friendlyName", BSL_CID_FRIENDLYNAME},
    {{9, "\52\206\110\206\367\15\1\11\25", BSL_OID_GLOBAL}, "localKeyId", BSL_CID_LOCALKEYID},
    {{9, "\52\206\110\206\367\15\1\7\1", BSL_OID_GLOBAL}, "data", BSL_CID_PKCS7_SIMPLEDATA},
    {{9, "\52\206\110\206\367\15\1\7\6", BSL_OID_GLOBAL}, "encryptedData", BSL_CID_PKCS7_ENCRYPTEDDATA},
    {{5, "\53\201\4\0\42", BSL_OID_GLOBAL}, "SECP384R1", BSL_CID_SECP384R1},
    {{5, "\53\201\4\0\43", BSL_OID_GLOBAL}, "SECP521R1", BSL_CID_SECP521R1},
    {{8, "\52\201\34\317\125\1\203\21", BSL_OID_GLOBAL}, "SM3", BSL_CID_SM3},
    {{10, "\52\201\34\317\125\1\203\21\3\1", BSL_OID_GLOBAL}, "HMAC-SM3", BSL_CID_HMAC_SM3},
    {{8, "\52\201\34\317\125\1\203\165", BSL_OID_GLOBAL}, "SM2DSAWITHSM3", BSL_CID_SM2DSAWITHSM3},
    {{8, "\52\201\34\317\125\1\203\166", BSL_OID_GLOBAL}, "SM2DSAWITHSHA1", BSL_CID_SM2DSAWITHSHA1},
    {{8, "\52\201\34\317\125\1\203\167", BSL_OID_GLOBAL}, "SM2DSAWITHSHA256", BSL_CID_SM2DSAWITHSHA256},
    {{8, "\52\201\34\317\125\1\202\55", BSL_OID_GLOBAL}, "SM2PRIME256", BSL_CID_SM2PRIME256},
    {{3, "\125\4\11", BSL_OID_GLOBAL}, "STREET", BSL_CID_AT_STREETADDRESS},
    {{5, "\53\201\4\0\41", BSL_OID_GLOBAL}, "PRIME224", BSL_CID_NIST_PRIME224},
    {{3, "\53\145\160", BSL_OID_GLOBAL}, "ED25519", BSL_CID_ED25519},
    {{9, "\52\206\110\206\367\15\1\1\12", BSL_OID_GLOBAL}, "RSASSAPSS", BSL_CID_RSASSAPSS},
    {{9, "\52\206\110\206\367\15\1\1\10", BSL_OID_GLOBAL}, "MGF1", BSL_CID_MGF1},
    {{8, "\52\201\34\317\125\1\150\2", BSL_OID_GLOBAL}, "SM4-CBC", BSL_CID_SM4_CBC},
    {{8, "\52\201\34\317\125\1\203\170", BSL_OID_GLOBAL}, "SM3WITHRSA", BSL_CID_SM3WITHRSAENCRYPTION},
    {{9, "\140\206\110\1\145\3\4\3\2", BSL_OID_GLOBAL}, "DSAWITHSHA256", BSL_CID_DSAWITHSHA256},
    {{9, "\140\206\110\1\145\3\4\3\1", BSL_OID_GLOBAL}, "DSAWITHSHA224", BSL_CID_DSAWITHSHA224},
    {{9, "\140\206\110\1\145\3\4\3\3", BSL_OID_GLOBAL}, "DSAWITHSHA384", BSL_CID_DSAWITHSHA384},
    {{9, "\140\206\110\1\145\3\4\3\4", BSL_OID_GLOBAL}, "DSAWITHSHA512", BSL_CID_DSAWITHSHA512},
    {{9, "\52\206\110\206\367\15\1\1\16", BSL_OID_GLOBAL}, "SHA224WITHRSA", BSL_CID_SHA224WITHRSAENCRYPTION},
    {{9, "\140\206\110\1\145\3\4\2\7", BSL_OID_GLOBAL}, "SHA3-224", BSL_CID_SHA3_224},
    {{9, "\140\206\110\1\145\3\4\2\10", BSL_OID_GLOBAL}, "SHA3-256", BSL_CID_SHA3_256},
    {{9, "\140\206\110\1\145\3\4\2\11", BSL_OID_GLOBAL}, "SHA3-384", BSL_CID_SHA3_384},
    {{9, "\140\206\110\1\145\3\4\2\12", BSL_OID_GLOBAL}, "SHA3-512", BSL_CID_SHA3_512},
    {{9, "\140\206\110\1\145\3\4\2\13", BSL_OID_GLOBAL}, "SHAKE128", BSL_CID_SHAKE128},
    {{9, "\140\206\110\1\145\3\4\2\14", BSL_OID_GLOBAL}, "SHAKE256", BSL_CID_SHAKE256},
    {{8, "\53\157\2\214\123\0\1\1", BSL_OID_GLOBAL}, "CID_AES128_XTS", BSL_CID_AES128_XTS},
    {{8, "\53\157\2\214\123\0\1\2", BSL_OID_GLOBAL}, "CID_AES256_XTS", BSL_CID_AES256_XTS},
    {{8, "\52\201\34\317\125\1\150\12", BSL_OID_GLOBAL}, "CID_SM4_XTS", BSL_CID_SM4_XTS},
    {{8, "\52\201\34\317\125\1\150\7", BSL_OID_GLOBAL}, "CID_SM4_CTR", BSL_CID_SM4_CTR},
    {{8, "\52\201\34\317\125\1\150\10", BSL_OID_GLOBAL}, "CID_SM4_GCM", BSL_CID_SM4_GCM},
    {{8, "\52\201\34\317\125\1\150\4", BSL_OID_GLOBAL}, "CID_SM4_CFB", BSL_CID_SM4_CFB},
    {{8, "\52\201\34\317\125\1\150\3", BSL_OID_GLOBAL}, "CID_SM4_OFB", BSL_CID_SM4_OFB},
    {{9, "\53\44\3\3\2\10\1\1\7", BSL_OID_GLOBAL}, "BRAINPOOLP256R1", BSL_CID_ECC_BRAINPOOLP256R1},
    {{9, "\53\44\3\3\2\10\1\1\13", BSL_OID_GLOBAL}, "BRAINPOOLP384R1", BSL_CID_ECC_BRAINPOOLP384R1},
    {{9, "\53\44\3\3\2\10\1\1\15", BSL_OID_GLOBAL}, "BRAINPOOLP512R1", BSL_CID_ECC_BRAINPOOLP512R1},
    {{7, "\52\206\110\316\75\2\1", BSL_OID_GLOBAL}, "EC-PUBLICKEY", BSL_CID_EC_PUBLICKEY}, // ecc subkey
    {{10, "\11\222\46\211\223\362\54\144\1\1", BSL_OID_GLOBAL}, "UID", BSL_CID_AT_USERID},
    {{9, "\140\206\110\1\145\3\4\3\21", BSL_OID_GLOBAL}, "ML-DSA-44", BSL_CID_ML_DSA_44},
    {{9, "\140\206\110\1\145\3\4\3\22", BSL_OID_GLOBAL}, "ML-DSA-65", BSL_CID_ML_DSA_65},
    {{9, "\140\206\110\1\145\3\4\3\23", BSL_OID_GLOBAL}, "ML-DSA-87", BSL_CID_ML_DSA_87},
    {{9, "\140\206\110\1\145\3\4\4\1", BSL_OID_GLOBAL}, "ML-KEM-512", BSL_CID_ML_KEM_512},
    {{9, "\140\206\110\1\145\3\4\4\2", BSL_OID_GLOBAL}, "ML-KEM-768", BSL_CID_ML_KEM_768},
    {{9, "\140\206\110\1\145\3\4\4\3", BSL_OID_GLOBAL}, "ML-KEM-1024", BSL_CID_ML_KEM_1024},
    {{9, "\140\206\110\1\145\3\4\3\24", BSL_OID_GLOBAL}, "SLH-DSA-SHA2-128S", BSL_CID_SLH_DSA_SHA2_128S},
    {{9, "\140\206\110\1\145\3\4\3\32", BSL_OID_GLOBAL}, "SLH-DSA-SHAKE-128S", BSL_CID_SLH_DSA_SHAKE_128S},
    {{9, "\140\206\110\1\145\3\4\3\25", BSL_OID_GLOBAL}, "SLH-DSA-SHA2-128F", BSL_CID_SLH_DSA_SHA2_128F},
    {{9, "\140\206\110\1\145\3\4\3\33", BSL_OID_GLOBAL}, "SLH-DSA-SHAKE-128F", BSL_CID_SLH_DSA_SHAKE_128F},
    {{9, "\140\206\110\1\145\3\4\3\26", BSL_OID_GLOBAL}, "SLH-DSA-SHA2-192S", BSL_CID_SLH_DSA_SHA2_192S},
    {{9, "\140\206\110\1\145\3\4\3\34", BSL_OID_GLOBAL}, "SLH-DSA-SHAKE-192S", BSL_CID_SLH_DSA_SHAKE_192S},
    {{9, "\140\206\110\1\145\3\4\3\27", BSL_OID_GLOBAL}, "SLH-DSA-SHA2-192F", BSL_CID_SLH_DSA_SHA2_192F},
    {{9, "\140\206\110\1\145\3\4\3\35", BSL_OID_GLOBAL}, "SLH-DSA-SHAKE-192F", BSL_CID_SLH_DSA_SHAKE_192F},
    {{9, "\140\206\110\1\145\3\4\3\30", BSL_OID_GLOBAL}, "SLH-DSA-SHA2-256S", BSL_CID_SLH_DSA_SHA2_256S},
    {{9, "\140\206\110\1\145\3\4\3\36", BSL_OID_GLOBAL}, "SLH-DSA-SHAKE-256S", BSL_CID_SLH_DSA_SHAKE_256S},
    {{9, "\140\206\110\1\145\3\4\3\31", BSL_OID_GLOBAL}, "SLH-DSA-SHA2-256F", BSL_CID_SLH_DSA_SHA2_256F},
    {{9, "\140\206\110\1\145\3\4\3\37", BSL_OID_GLOBAL}, "SLH-DSA-SHAKE-256F", BSL_CID_SLH_DSA_SHAKE_256F},
    {{3, "\125\35\22", BSL_OID_GLOBAL}, "IssuerAlternativeName", BSL_CID_CE_ISSUERALTERNATIVENAME},
    {{8, "\53\6\1\5\5\7\1\1", BSL_OID_GLOBAL}, "AuthorityInformationAccess", BSL_CID_CE_AUTHORITYINFORMATIONACCESS},
    {{8, "\53\6\1\5\5\7\6\42", BSL_OID_GLOBAL}, "XMSS", BSL_CID_XMSS}, // XMSS
    {{10, "\52\206\110\206\367\15\1\11\27\1", BSL_OID_GLOBAL}, "x509crl", BSL_CID_X509CRL},
};

uint32_t g_tableSize = (uint32_t)sizeof(g_oidTable)/sizeof(g_oidTable[0]);

#ifdef HITLS_BSL_OBJ_CUSTOM
static void FreeBslOidInfo(void *data)
{
    if (data == NULL) {
        return;
    }
    BslOidInfo *oidInfo = (BslOidInfo *)data;
    BSL_SAL_Free(oidInfo->strOid.octs);
    BSL_SAL_Free((char *)(uintptr_t)oidInfo->oidName);
    BSL_SAL_Free(oidInfo);
}

static void InitOidHashTableOnce(void)
{
    int32_t ret = BSL_SAL_ThreadLockNew(&g_oidHashRwLock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return;
    }

    ListDupFreeFuncPair valueFunc = {NULL, FreeBslOidInfo};
    g_oidHashTable = BSL_HASH_Create(BSL_OBJ_HASH_BKT_SIZE, NULL, NULL, NULL, &valueFunc);
    if (g_oidHashTable == NULL) {
        (void)BSL_SAL_ThreadLockFree(g_oidHashRwLock);
        g_oidHashRwLock = NULL;
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
    }
}
#endif // HITLS_BSL_OBJ_CUSTOM

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

BslCid BSL_OBJ_GetCidFromOidBuff(const uint8_t *oid, uint32_t len)
{
    if (oid == NULL || len == 0) {
        return BSL_CID_UNKNOWN;
    }

    /* First, search in the g_oidTable */
    for (uint32_t i = 0; i < g_tableSize; i++) {
        if (g_oidTable[i].strOid.octetLen == len) {
            if (memcmp(g_oidTable[i].strOid.octs, oid, len) == 0) {
                return g_oidTable[i].cid;
            }
        }
    }
#ifndef HITLS_BSL_OBJ_CUSTOM
    return BSL_CID_UNKNOWN;
#else
    if (g_oidHashTable == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_OBJ_INVALID_HASH_TABLE);
        return BSL_CID_UNKNOWN;
    }

    /* Second, search in the g_oidHashTable with read lock */
    BslCid cid = BSL_CID_UNKNOWN;
    int32_t ret = BSL_SAL_ThreadReadLock(g_oidHashRwLock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return BSL_CID_UNKNOWN;
    }

    /* Since g_oidHashTable is keyed by cid, we need to iterate through all entries */
    BSL_HASH_Iterator iter = BSL_HASH_IterBegin(g_oidHashTable);
    BSL_HASH_Iterator end = BSL_HASH_IterEnd(g_oidHashTable);
    
    while (iter != end) {
        BslOidInfo *oidInfo = (BslOidInfo *)BSL_HASH_IterValue(g_oidHashTable, iter);
        if (oidInfo != NULL && oidInfo->strOid.octetLen == len &&
            memcmp(oidInfo->strOid.octs, oid, len) == 0) {
            cid = oidInfo->cid;
            break;
        }
        iter = BSL_HASH_IterNext(g_oidHashTable, iter);
    }

    (void)BSL_SAL_ThreadUnlock(g_oidHashRwLock);
    return cid;
#endif // HITLS_BSL_OBJ_CUSTOM
}

BslCid BSL_OBJ_GetCID(const BslOidString *oidstr)
{
    if (oidstr == NULL) {
        return BSL_CID_UNKNOWN;
    }
    return BSL_OBJ_GetCidFromOidBuff((const uint8_t *)oidstr->octs, oidstr->octetLen);
}

BslOidString *BSL_OBJ_GetOID(BslCid ulCID)
{
    if (ulCID == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return NULL;
    }

    /* First, search in the g_oidTable */
    int32_t index = GetOidIndex(ulCID);
    if (index != -1) {
        return &g_oidTable[index].strOid;
    }
#ifndef HITLS_BSL_OBJ_CUSTOM
    return NULL;
#else

    /* Initialize hash table if needed */
    if (g_oidHashTable == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_OBJ_INVALID_HASH_TABLE);
        return NULL;
    }

    /* Second, search in the g_oidHashTable with read lock */
    BslOidInfo *oidInfo = NULL;
    int32_t ret = BSL_SAL_ThreadReadLock(g_oidHashRwLock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }

    /* Since g_oidHashTable is keyed by cid, we can directly look up the entry */
    ret = BSL_HASH_At(g_oidHashTable, (uintptr_t)ulCID, (uintptr_t *)&oidInfo);
    (void)BSL_SAL_ThreadUnlock(g_oidHashRwLock);
    BslOidString *oidString = (ret == BSL_SUCCESS && oidInfo != NULL) ? &oidInfo->strOid : NULL;
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_OBJ_ERR_FIND_HASH_TABLE);
    }

    return oidString;
#endif // HITLS_BSL_OBJ_CUSTOM
}

const char *BSL_OBJ_GetOidNameFromOidBuff(const uint8_t *oid, uint32_t len)
{
    if (oid == NULL || len == 0) {
        return NULL;
    }

    /* First, search in the g_oidTable */
    for (uint32_t i = 0; i < g_tableSize; i++) {
        if (g_oidTable[i].strOid.octetLen == len) {
            if (memcmp(g_oidTable[i].strOid.octs, oid, len) == 0) {
                return g_oidTable[i].oidName;
            }
        }
    }
#ifndef HITLS_BSL_OBJ_CUSTOM
    return NULL;
#else
    if (g_oidHashTable == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_OBJ_INVALID_HASH_TABLE);
        return NULL;
    }

    /* Second, search in the g_oidHashTable with read lock */
    const char *oidName = NULL;
    int32_t ret = BSL_SAL_ThreadReadLock(g_oidHashRwLock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }

    /* Since g_oidHashTable is keyed by cid, we need to iterate through all entries */
    BSL_HASH_Iterator iter = BSL_HASH_IterBegin(g_oidHashTable);
    BSL_HASH_Iterator end = BSL_HASH_IterEnd(g_oidHashTable);

    while (iter != end) {
        BslOidInfo *oidInfo = (BslOidInfo *)BSL_HASH_IterValue(g_oidHashTable, iter);
        if (oidInfo != NULL && oidInfo->strOid.octetLen == len &&
            memcmp(oidInfo->strOid.octs, oid, len) == 0) {
            oidName = oidInfo->oidName;
            break;
        }
        iter = BSL_HASH_IterNext(g_oidHashTable, iter);
    }

    (void)BSL_SAL_ThreadUnlock(g_oidHashRwLock);
    return oidName;
#endif // HITLS_BSL_OBJ_CUSTOM
}

const char *BSL_OBJ_GetOidNameFromOid(const BslOidString *oid)
{
    if (oid == NULL) {
        return NULL;
    }
    return BSL_OBJ_GetOidNameFromOidBuff((const uint8_t *)oid->octs, oid->octetLen);
}

#if defined(HITLS_PKI_X509) || defined(HITLS_PKI_INFO)

/**
 * RFC 5280: A.1. Explicitly Tagged Module, 1988 Syntax
 * -- Upper Bounds
*/

static const BslAsn1DnInfo g_asn1DnTab[] = {
    {BSL_CID_AT_COMMONNAME, 1, 64, "CN"}, // ub-common-name INTEGER ::= 64
    {BSL_CID_AT_SURNAME, 1, 40, "SN"}, // ub-surname-length INTEGER ::= 40
    {BSL_CID_AT_SERIALNUMBER, 1, 64, "serialNumber"}, // ub-serial-number INTEGER ::= 64
    {BSL_CID_AT_COUNTRYNAME, 2, 2, "C"}, // ub-country-name-alpha-length INTEGER ::= 2
    {BSL_CID_AT_LOCALITYNAME, 1, 128, "L"}, // ub-locality-name INTEGER ::= 128
    {BSL_CID_AT_STATEORPROVINCENAME, 1, 128, "ST"}, // ub-state-name INTEGER ::= 128
    {BSL_CID_AT_STREETADDRESS, 1, -1, "street"}, // no limited
    {BSL_CID_AT_ORGANIZATIONNAME, 1, 64, "O"}, // ub-organization-name INTEGER ::= 64
    {BSL_CID_AT_ORGANIZATIONALUNITNAME, 1, 64, "OU"}, // ub-organizational-unit-name INTEGER ::= 64
    {BSL_CID_AT_TITLE, 1, 64, "title"}, // ub-title INTEGER ::= 64
    {BSL_CID_AT_GIVENNAME, 1, 32768, "GN"}, // ub-name INTEGER ::= 32768
    {BSL_CID_AT_INITIALS, 1, 32768, "initials"}, // ub-name INTEGER ::= 32768
    {BSL_CID_AT_GENERATIONQUALIFIER, 1, 32768, "generationQualifier"}, // ub-name INTEGER ::= 32768
    {BSL_CID_AT_DNQUALIFIER, 1, -1, "dnQualifier"}, // no limited
    {BSL_CID_AT_PSEUDONYM, 1, 128, "pseudonym"}, // ub-pseudonym INTEGER ::= 128
    {BSL_CID_DOMAINCOMPONENT, 1, -1, "DC"}, // no limited
    {BSL_CID_AT_USERID, 1, 256, "UID"}, // RFC1274
};

#define BSL_DN_STR_CNT (sizeof(g_asn1DnTab) / sizeof(g_asn1DnTab[0]))

const BslAsn1DnInfo *BSL_OBJ_GetDnInfoFromShortName(const char *shortName)
{
    for (size_t i = 0; i < BSL_DN_STR_CNT; i++) {
        if (strcmp(g_asn1DnTab[i].shortName, shortName) == 0) {
            return &g_asn1DnTab[i];
        }
    }

    return NULL;
}

const BslAsn1DnInfo *BSL_OBJ_GetDnInfoFromCid(BslCid cid)
{
    for (size_t i = 0; i < sizeof(g_asn1DnTab) / sizeof(g_asn1DnTab[0]); i++) {
        if (cid == g_asn1DnTab[i].cid) {
            return &g_asn1DnTab[i];
        }
    }

    return NULL;
}

#endif // HITLS_PKI_X509 || HITLS_PKI_INFO

#if defined(HITLS_PKI_X509) || defined(HITLS_PKI_INFO) || defined(HITLS_CRYPTO_KEY_INFO)

const char *BSL_OBJ_GetOidNameFromCID(BslCid ulCID)
{
    if (ulCID >= BSL_CID_MAX) { /* check if ulCID is within range */
        return NULL;
    }
    int32_t index = GetOidIndex(ulCID);
    if (index == -1) {
        return NULL;
    }
    return g_oidTable[index].oidName;
}

#endif // HITLS_PKI_X509 || HITLS_PKI_INFO || HITLS_CRYPTO_KEY_INFO


#ifdef HITLS_BSL_OBJ_CUSTOM
static int32_t BslOidStringCopy(const BslOidString *srcOidStr, BslOidString *oidString)
{
    oidString->octs = BSL_SAL_Dump(srcOidStr->octs, srcOidStr->octetLen);
    if (oidString->octs == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    oidString->octetLen = srcOidStr->octetLen;
    oidString->flags = srcOidStr->flags;
    return BSL_SUCCESS;
}

static bool IsOidCidInStaticTable(int32_t cid)
{
    for (uint32_t i = 0; i < g_tableSize; i++) {
        if ((int32_t)g_oidTable[i].cid == cid) {
            return true;
        }
    }
    return false;
}

static int32_t IsOidCidInHashTable(int32_t cid)
{
    BslOidInfo *oidInfo = NULL;
    int32_t ret = BSL_SAL_ThreadReadLock(g_oidHashRwLock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = BSL_HASH_At(g_oidHashTable, (uintptr_t)cid, (uintptr_t *)&oidInfo);
    (void)BSL_SAL_ThreadUnlock(g_oidHashRwLock);
    return ret;
}

static int32_t CreateOidInfo(const BslOidString *oid, const char *oidName, int32_t cid, BslOidInfo **newOidInfo)
{
    BslOidInfo *oidInfo = (BslOidInfo *)BSL_SAL_Calloc(1, sizeof(BslOidInfo));
    if (oidInfo == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    int32_t ret = BslOidStringCopy(oid, &oidInfo->strOid);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        BSL_SAL_Free(oidInfo);
        return ret;
    }

    oidInfo->oidName = BSL_SAL_Dump(oidName, (uint32_t)strlen(oidName) + 1);
    if (oidInfo->oidName == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        BSL_SAL_Free(oidInfo->strOid.octs);
        BSL_SAL_Free(oidInfo);
        return BSL_MALLOC_FAIL;
    }

    oidInfo->cid = cid;
    *newOidInfo = oidInfo;
    return BSL_SUCCESS;
}

// Insert OID info into hash table with write lock
static int32_t InsertOidInfoToHashTable(int32_t cid, BslOidInfo *oidInfo)
{
    int32_t ret = BSL_SAL_ThreadWriteLock(g_oidHashRwLock);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    BslOidInfo *checkInfo = NULL;
    ret = BSL_HASH_At(g_oidHashTable, (uintptr_t)cid, (uintptr_t *)&checkInfo);
    if (ret == BSL_SUCCESS) {
        (void)BSL_SAL_ThreadUnlock(g_oidHashRwLock);
        return BSL_SUCCESS;
    }

    ret = BSL_HASH_Insert(g_oidHashTable, (uintptr_t)cid, sizeof(int32_t), (uintptr_t)oidInfo, sizeof(BslOidInfo));
    (void)BSL_SAL_ThreadUnlock(g_oidHashRwLock);
    return ret;
}

// Main function for creating and registering OIDs
int32_t BSL_OBJ_Create(char *octs, uint32_t octetLen, const char *oidName, int32_t cid)
{
    if (octs == NULL || octetLen == 0 || oidName == NULL || cid == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }

    if (IsOidCidInStaticTable(cid)) {
        return BSL_SUCCESS;
    }
    const BslOidString oid = {
        .octs = octs,
        .octetLen = octetLen,
        .flags = 6
    };

    int32_t ret = BSL_SAL_ThreadRunOnce(&g_oidHashInitOnce, InitOidHashTableOnce);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (g_oidHashTable == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_OBJ_INVALID_HASH_TABLE);
        return BSL_OBJ_INVALID_HASH_TABLE;
    }
    ret = IsOidCidInHashTable(cid);
    if (ret == BSL_SUCCESS) {
        return BSL_SUCCESS;
    }

    BslOidInfo *oidInfo = NULL;
    ret = CreateOidInfo(&oid, oidName, cid, &oidInfo);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    ret = InsertOidInfoToHashTable(cid, oidInfo);
    if (ret != BSL_SUCCESS) {
        FreeBslOidInfo(oidInfo);
        return ret;
    }

    return BSL_SUCCESS;
}

void BSL_OBJ_FreeHashTable(void)
{
    if (g_oidHashTable != NULL) {
        int32_t ret = BSL_SAL_ThreadWriteLock(g_oidHashRwLock);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return;
        }
        BSL_HASH_Destroy(g_oidHashTable);
        g_oidHashTable = NULL;
        (void)BSL_SAL_ThreadUnlock(g_oidHashRwLock);
        if (g_oidHashRwLock != NULL) {
            (void)BSL_SAL_ThreadLockFree(g_oidHashRwLock);
            g_oidHashRwLock = NULL;
        }
        (void)memset_s(&g_oidHashInitOnce, sizeof(g_oidHashInitOnce), 0, sizeof(g_oidHashInitOnce));
    }
}
#endif // HITLS_BSL_OBJ_CUSTOM

/*
* Conversion Rules:
* The first byte represents the first two nodes: X.Y, where X = first byte / 40, Y = first byte % 40.
* Subsequent nodes use variable length encoding (Base 128), where the highest bit of each byte indicates
* whether there are subsequent bytes (1 indicates continuation, 0 indicates end).
* Detailed conversion process:
* 1、Split the first two nodes, the first byte is decomposed into two numbers: first_node and second_node,
* first_node = byte_value / 40, second_node = byte_value % 40.
* 2、Decoding subsequent nodes, Each node may be composed of multiple bytes, with the most significant bit (MSB)
* of each byte being the continuation flag and the remaining 7 bits being a part of the actual value,
* Multiple 7-bit groups are combined in big endian order.
*/
char *BSL_OBJ_GetOidNumericString(const uint8_t *oid, uint32_t len)
{
    if (oid == NULL || len < 1 || oid[0] > BSL_OBJ_ARCS_MAX) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return NULL;
    }

    char buffer[256] = {0};
    if (snprintf_s(buffer, sizeof(buffer), sizeof(buffer) - 1, "%d.%d", oid[0] / BSL_OBJ_ARCS_Y_MAX,
        oid[0] % BSL_OBJ_ARCS_Y_MAX) < 0) {
        return NULL;
    }

    uint64_t value = 0;
    uint32_t currentPos = strlen(buffer);
    for (uint32_t i = 1; i < len; i++) {
        if (value > (UINT64_MAX >> 7)) {
            /* Overflow check */
            BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
            return NULL;
        }
        if ((value == 0) && ((oid[i]) == 0x80)) {
            /* Any value must be encoded with the minimum number of bytes.
              No unnecessary or meaningless leading bytes are allowed */
            BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
            return NULL;
        }

        value = (value << 7) | (oid[i] & 0x7F);
        if (!(oid[i] & 0x80)) {
            char temp[20] = {0};
            int32_t tempLen = snprintf_s(temp, sizeof(temp), sizeof(temp) - 1, ".%lu", value);
            if (tempLen < 0) {
                BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
                return NULL;
            }
            if (currentPos + tempLen >= sizeof(buffer)) {
                BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
                return NULL;
            }
            if (memcpy_s(buffer + currentPos, tempLen, temp, tempLen) != 0) {
                BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
                return NULL;
            }
            currentPos += tempLen;
            value = 0;
        }
    }

    if (value != 0) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return NULL;
    }

    return BSL_SAL_Dump(buffer, sizeof(buffer));
}

static void BslEncodeOidPart(uint64_t num, uint8_t *output, uint32_t *offset)
{
    if (num < 0x80) {
        output[*offset] = num &0x7F;
        (*offset)++;
    } else {
        uint8_t temp[10]; // The data of uint64_t requires up to 10 bytes when encode in ASN1.
        int32_t i = 0;
        uint64_t t = num;
        while (t > 0) {
            temp[i] = (t & 0x7F) | 0x80;
            i++;
            t >>= 7; // Process 7 bits each time.
        }

        temp[0] &= 0x7F;
        for (int32_t j = i - 1; j >= 0; j--) {
            output[*offset] = temp[j];
            (*offset)++;
        }
    }
}

static bool BslEncodeOidValueCheck(uint64_t *parts, uint32_t count)
{
    // At least 2 pieces of data are required.
    if (count < 2 || parts[0] > BSL_OBJ_ARCS_X_MAX) {
        return false;
    }
    if (parts[1] >= BSL_OBJ_ARCS_Y_MAX) {
        return false;
    }
    return true;
}

#define MAX_OID_PARTS_LEN 128
uint8_t *BSL_OBJ_GetOidFromNumericString(const char *oid, uint32_t len, uint32_t *outLen)
{
    if (len == 0 || oid == NULL || oid[0] == '.' || outLen == NULL || oid[len - 1] == '.') {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return NULL;
    }
    uint64_t parts[MAX_OID_PARTS_LEN];
    uint32_t count = 0;
    parts[count] = 0;

    for (uint32_t i = 0; i < len; i++) {
        if (oid[i] > '9' || (oid[i] < '0' && oid[i] != '.')) {
            BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
            return NULL;
        }
        if ((i < len - 1) && oid[i] == '.' && oid[i + 1] == '.') {
            BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
            return NULL;
        }
        if (oid[i] != '.') {
            // Convert decimal string to number.
            if (parts[count] > (UINT64_MAX - (oid[i] - '0')) / 10) {
                BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
                return NULL;
            }
            parts[count] = parts[count] * 10 + (oid[i] - '0');
        } else {
            count++;
            if (count >= MAX_OID_PARTS_LEN) {
                BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
                return NULL;
            }
            parts[count] = 0;
        }
    }
    count++;

    if (BslEncodeOidValueCheck(parts, count) != true) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return NULL;
    }

    uint32_t offset = 0;
    // The data of uint64_t requires up to 10 bytes when encode in ASN1.
    uint8_t *outBuf = BSL_SAL_Malloc(count * 10);
    if (outBuf == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    outBuf[0] = (uint8_t)(parts[0] * BSL_OBJ_ARCS_Y_MAX + parts[1]);
    offset++;

    for (uint32_t i = 2; i < count; i++) {
        BslEncodeOidPart(parts[i], outBuf, &offset);
    }
    *outLen = offset;
    return outBuf;
}

#endif
