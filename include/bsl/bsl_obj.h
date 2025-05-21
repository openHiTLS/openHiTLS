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

/**
 * @defgroup bsl_obj
 * @ingroup bsl
 * @brief object module
 */

#ifndef BSL_OBJ_H
#define BSL_OBJ_H

#include <stdbool.h>
#include <stdint.h>
#include "bsl_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup bsl_obj
 * All algorithm ID
 */
typedef enum {
    BSL_CID_UNKNOWN = 0,       /**< Unknown alg id */

    BSL_CID_RC4 = 1,          /* identifies the RC4 algorithm */
    BSL_CID_DES_ECB = 2,      /* identifies DES algorithm in ECB mode */
    BSL_CID_DES_CBC = 3,      /* identifies DES algorithm in CBC mode */
    BSL_CID_DES_OFB = 4,      /* identifies DES algorithm in OFB mode */
    BSL_CID_DES_CFB = 5,      /* identifies DES algorithm in CFB mode */
    BSL_CID_SCB2_128_ECB = 6, /* identifies SCB2-128 algorithm in ECB mode */
    BSL_CID_SCB2_128_CBC = 7, /* identifies SCB2-128 algorithm in CBC mode */
    BSL_CID_SCB2_256_ECB = 8, /* identifies SCB2-256 algorithm in ECB mode */
    BSL_CID_SCB2_256_CBC = 9,

    BSL_CID_DES_EDE_ECB = 10,  /* identifies 2 key triple DES algorithm in ECB mode */
    BSL_CID_DES_EDE_CBC = 11,  /* identifies 2 key triple DES algorithm in CBC mode */
    BSL_CID_DES_EDE_OFB = 12,  /* identifies 2 key triple DES algorithm in OFB mode */
    BSL_CID_DES_EDE_CFB = 13,  /* identifies 2 key triple DES algorithm in CFB mode */
    BSL_CID_DES_EDE3_ECB = 14, /* identifies 3 key triple DES algorithm in ECB mode */
    BSL_CID_DES_EDE3_CBC = 15, /* identifies 3 key triple DES algorithm in CBC mode */
    BSL_CID_DES_EDE3_OFB = 16, /* identifies 3 key triple DES algorithm in OFB mode */
    BSL_CID_DES_EDE3_CFB = 17, /* identifies 3 key triple DES algorithm in CFB mode */
    BSL_CID_AES128_ECB = 18,   /* identifies AES-128 algorithm in ECB mode */
    BSL_CID_AES128_CBC = 19,   /* identifies AES-128 algorithm in CBC mode */
    BSL_CID_AES128_OFB = 20,   /* identifies AES-128 algorithm in OFB mode */
    BSL_CID_AES128_CFB = 21,   /* identifies AES-128 algorithm in CFB mode */
    BSL_CID_AES192_ECB = 22,   /* identifies AES-192 algorithm in ECB mode */
    BSL_CID_AES192_CBC = 23,   /* identifies AES-192 algorithm in CBC mode */
    BSL_CID_AES192_OFB = 24,   /* identifies AES-192 algorithm in OFB mode */
    BSL_CID_AES192_CFB = 25,   /* identifies AES-192 algorithm in CFB mode */
    BSL_CID_AES256_ECB = 26,   /* identifies AES-256 algorithm in ECB mode */
    BSL_CID_AES256_CBC = 27,   /* identifies AES-256 algorithm in CBC mode */
    BSL_CID_AES256_OFB = 28,   /* identifies AES-256 algorithm in OFB mode */
    BSL_CID_AES256_CFB = 29,   /* identifies AES-256 algorithm in CFB mode */
    BSL_CID_KASUMI_ECB = 30,   /* identifies Kasumi algorithm in ECB mode */
    BSL_CID_KASUMI_CBC = 31,   /* identifies Kasumi algorithm in CBC mode */
    BSL_CID_KASUMI_OFB = 32,   /* identifies Kasumi algorithm in OFB mode */
    BSL_CID_KASUMI_CFB = 33,   /* identifies Kasumi algorithm in CFB mode */
    BSL_CID_RSA = 34,          /* identifies the RSA algorithm */
    BSL_CID_DSA = 35,          /* identifies the DSA algorithm */
    BSL_CID_ECDSA = 36,        /* identifies the ECDSA algorithm */
    BSL_CID_ECDSA192 = 37,     /* identifies the ECDSA192 algorithm */
    BSL_CID_DH = 38,           /* identifies the Diffie-Hellman algorithm */
    BSL_CID_ECDH = 39,         /* identifies the EC Diffie-Hellman algorithm */
    BSL_CID_MD5 = 40,          /* identifies the MD5 hash algorithm */
    BSL_CID_SHA1 = 41,         /* identifies the SHA1 hash algorithm */
    BSL_CID_SHA224 = 42,       /* identifies the SHA224 hash algorithm */
    BSL_CID_SHA256 = 43,       /* identifies the SHA256 hash algorithm */
    BSL_CID_SHA384 = 44,       /* identifies the SHA384 hash algorithm */
    BSL_CID_SHA512 = 45,       /* identifies the SHA512 hash algorithm */
    BSL_CID_HMAC_MD5 = 46,     /* identifies hmac with MD5 */
    BSL_CID_HMAC_SHA1 = 47,    /* identifies hmac with SHA1 */
    BSL_CID_HMAC_SHA224 = 48,  /* identifies hmac with SHA224 */
    BSL_CID_HMAC_SHA256 = 49,  /* identifies hmac with SHA256 */
    BSL_CID_HMAC_SHA384 = 50,  /* identifies hmac with SHA384 */
    BSL_CID_HMAC_SHA512 = 51,  /* identifies hmac with SHA512 */

    BSL_CID_MD5WITHRSA = 52,   /* identifies signature using MD5 and RSA */
    BSL_CID_SHA1WITHRSA = 53,  /* identifies signature using SHA1 and RSA */
    BSL_CID_SHA1WITHRSAOLD = 54,     /* identifies signature using SHA1 and RSA (coresponds to old Oid) */
    BSL_CID_DSAWITHSHA1 = 55,        /* identifies signature using SHA1 and DSA */
    BSL_CID_DSAWITHSHA1_2 = 56,      /* identifies signature using SHA1 and DSA */
    BSL_CID_ECDSAWITHSHA1 = 57,      /* identifies signature using SHA1 and ECDSA */
    BSL_CID_ECDSAWITHSHA224 = 58,    /* identifies signature using SHA224 and ECDSA */
    BSL_CID_ECDSAWITHSHA256 = 59,    /* identifies signature using SHA256 and ECDSA */
    BSL_CID_ECDSAWITHSHA384 = 60,    /* identifies signature using SHA384 and ECDSA */
    BSL_CID_ECDSAWITHSHA512 = 61,    /* identifies signature using SHA512 and ECDSA */
    BSL_CID_ECDSA192WITHSHA256 = 62, /* identifies signature using SHA256 and ECDSA-192 bit */

    BSL_CID_SHA256WITHRSAENCRYPTION = 63, /* identifies signature using SHA256 and RSA */

    BSL_CID_SHA384WITHRSAENCRYPTION = 64, /* identifies signature using SHA384 and RSA */
    BSL_CID_SHA512WITHRSAENCRYPTION = 65, /* identifies signature using SHA512 and RSA */

    /* RFC 3279 */
    BSL_CID_KEYEXCHANGEALGORITHM = 66,     /* identifies Key exchange algorithm */
    BSL_CID_PKCS1 = 67,                    /* identifies PKCS1 */
    BSL_CID_ANSI_X9_62 = 68,               /* identifies ANSI_X9_62 */
    BSL_CID_ECSIGTYPE = 69,                /* identifies ECSIGTYPE */
    BSL_CID_FIELDTYPE = 70,                /* identifies Field Type */
    BSL_CID_PRIME_FIELD = 71,              /* identifies PRIME Field */
    BSL_CID_CHARACTERISTIC_TWO_FIELD = 72, /* identifies Characterstic Two field */
    BSL_CID_CHARACTERISTIC_TWO_BASIS = 73, /* identifies Characterstic Two Basis */
    BSL_CID_GNBASIS = 74,                  /* identifies GNBASIS */
    BSL_CID_TPBASIS = 75,                  /* identifies TPBASIS */
    BSL_CID_PPBASIS = 76,                  /* identifies PPBASIS */
    BSL_CID_PUBLICKEYTYPE = 77,            /* identifies PUBLICKEYTYPE */
    BSL_CID_ELLIPTICCURVE = 78,            /* identifies ELLIPTICCURVE */
    BSL_CID_C_TWOCURVE = 79,               /* identifies C_TWOCURVE */
    BSL_CID_C2PNB163V1 = 80,               /* identifies C2PNB163V1 */
    BSL_CID_C2PNB163V2 = 81,               /* identifies C2PNB163V2 */
    BSL_CID_C2PNB163V3 = 82,               /* identifies C2PNB163V3 */
    BSL_CID_C2PNB176W1 = 83,               /* identifies C2PNB176W1 */
    BSL_CID_C2TNB191V1 = 84,               /* identifies C2TNB191V1 */
    BSL_CID_C2TNB191V2 = 85,               /* identifies C2TNB191V2 */
    BSL_CID_C2TNB191V3 = 86,               /* identifies C2TNB191V3 */
    BSL_CID_C2ONB191V4 = 87,               /* identifies C2ONB191V4 */
    BSL_CID_C2ONB191V5 = 88,               /* identifies C2ONB191V5 */
    BSL_CID_C2PNB208W1 = 89,               /* identifies C2PNB208W1 */
    BSL_CID_C2TNB239V1 = 90,               /* identifies C2TNB239V1 */
    BSL_CID_C2TNB239V2 = 91,               /* identifies C2TNB239V2 */
    BSL_CID_C2TNB239V3 = 92,               /* identifies C2TNB239V3 */
    BSL_CID_C2ONB239V4 = 93,               /* identifies C2ONB239V4 */
    BSL_CID_C2ONB239V5 = 94,               /* identifies C2ONB239V5 */
    BSL_CID_C2PNB272W1 = 95,               /* identifies C2PNB272W1 */
    BSL_CID_C2PNB304W1 = 96,               /* identifies C2PNB304W1 */
    BSL_CID_C2TNB359V1 = 97,               /* identifies C2TNB359V1 */
    BSL_CID_C2PNB368W1 = 98,               /* identifies C2PNB368W1 */
    BSL_CID_C2TNB431R1 = 99,               /* identifies C2TNB431R1 */
    BSL_CID_PRIMECURVE = 100,               /* identifies PRIMECURVE */
    BSL_CID_PRIME192V1 = 101,               /* identifies PRIME192V1 */
    BSL_CID_PRIME192V2 = 102,               /* identifies PRIME192V2 */
    BSL_CID_PRIME192V3 = 103,               /* identifies PRIME192V3 */
    BSL_CID_PRIME239V1 = 104,               /* identifies PRIME239V1 */
    BSL_CID_PRIME239V2 = 105,               /* identifies PRIME239V2 */
    BSL_CID_PRIME239V3 = 106,               /* identifies PRIME239V3 */
    BSL_CID_PRIME256V1 = 107,               /* identifies PRIME256V1 */
    /* SCEP */
    BSL_CID_VERISIGN = 108,       /* identifies VERISIGN */
    BSL_CID_PKI = 109,            /* identifies PKI */
    BSL_CID_ATTRIBUTES = 110,     /* identifies ATTRIBUTES */
    BSL_CID_MESSAGETYPE = 111,    /* identifies MESSAGETYPE */
    BSL_CID_PKISTATUS = 112,      /* identifies PKISTATUS */
    BSL_CID_FAILINFO = 113,       /* identifies FAILINFO */
    BSL_CID_SENDERNONCE = 114,    /* identifies SENDERNONCE */
    BSL_CID_RECIPIENTNONCE = 115, /* identifies RECIPIENTNONCE */
    BSL_CID_TRANSID = 116,        /* identifies TRANSID */
    BSL_CID_EXTENSIONREQ = 117,   /* identifies EXTENSIONREQ */
    /* PKCS 5 */
    BSL_CID_RSADSI = 118, /* identifies RSADSI */
    BSL_CID_PKCS = 119,   /* identifies PKCS */
    BSL_CID_PKCS5 = 120,  /* identifies PKCS5 */
    BSL_CID_PBKDF2 = 121, /* identifies PBKDF2 */
    BSL_CID_PBE_MD2WITHDESCBC  = 122,
    BSL_CID_PBE_MD2WITHRC2CBC = 123,
    BSL_CID_PBE_MD5WITHDESCBC = 124, /* identifies PBE_MD5WITHDESCBC */
    BSL_CID_PBE_MD5WITHRC2CBC = 125,
    BSL_CID_PBE_SHA1WITHDESCBC = 126, /* identifies PBE_SHA1WITHDESCBC */
    BSL_CID_PBE_SHA1WITHRC2CBC = 127,
    BSL_CID_PBES2 = 128,               /* identifies PBES2 */
    BSL_CID_PBMAC1 = 129,              /* identifies PBMAC1 */
    BSL_CID_DIGESTALGORITHM = 130,     /* identifies DIGESTALGORITHM */
    BSL_CID_ENCRYPTIONALGORITHM = 131, /* identifies ENCRYPTIONALGORITHM */
    BSL_CID_RC2CBC = 132,              /* identifies RC2CBC */
    BSL_CID_RC5_CBC_PAD = 133,         /* identifies RC5_CBC_PAD */
    BSL_CID_RSAES_OAEP = 134,          /* from pkcs1 */ /* identifies RSAES_OAEP */

    /* OCSP */
    BSL_CID_PKIX_OCSP_BASIC = 135,           /* identifies OCSP_BASIC */
    BSL_CID_PKIX_OCSP_NONCE = 136,           /* identifies OCSP_NONCE */
    BSL_CID_PKIX_OCSP_CRL = 137,             /* identifies OCSP_CRL */
    BSL_CID_PKIX_OCSP_RESPONSE = 138,        /* identifies OCSP_RESPONSE */
    BSL_CID_PKIX_OCSP_NOCHECK = 139,         /* identifies OCSP_NOCHECK */
    BSL_CID_PKIX_OCSP_ARCHIVE_CUTOFF = 140,  /* identifies OCSP_ARCHIVE_CUTOFF */
    BSL_CID_PKIX_OCSP_SERVICE_LOCATOR = 141, /* identifies OCSP_SERVICE_LOCATOR */
    /* PKCS 10 */
    BSL_CID_CHALLENGE_PWD_ATTR = 142, /* identifies Challenge PWD Attr */
    BSL_CID_EXTENSIONREQUEST = 143,   /* identifies EXTENSIONREQUEST */
    /* FROM PKIXEXPLICIT */
    BSL_CID_PKIX = 144,                      /* identifies PKIX */
    BSL_CID_PE = 145,                        /* identifies PE */
    BSL_CID_QT = 146,                        /* identifies QT */
    BSL_CID_KP = 147,                        /* identifies KP */
    BSL_CID_AD = 148,                        /* identifies AD */
    BSL_CID_QT_CPS = 149,                    /* identifies CPS */
    BSL_CID_QT_UNOTICE = 150,                /* identifies UNOTICE */
    BSL_CID_AD_OCSP = 151,                   /* identifies OCSP */
    BSL_CID_AD_CAISSUERS = 152,              /* identifies CAISSUERS */
    BSL_CID_AD_TIMESTAMPING = 153,           /* identifies TIMESTAMPING */
    BSL_CID_AD_CAREPOSITORY = 154,           /* identifies CAREPOSITORY */
    BSL_CID_AT = 155,                        /* identifies AT */
    BSL_CID_AT_NAME = 156,                   /* identifies NAME */
    BSL_CID_AT_SURNAME = 157,                /* identifies SURNAME */
    BSL_CID_AT_GIVENNAME = 158,              /* identifies GIVENNAME */
    BSL_CID_AT_INITIALS = 159,               /* identifies INITIALS */
    BSL_CID_AT_GENERATIONQUALIFIER = 160,    /* identifies GENERATIONQUALIFIER */
    BSL_CID_AT_COMMONNAME = 161,             /* identifies COMMONNAME */
    BSL_CID_AT_LOCALITYNAME = 162,           /* identifies LOCALITYNAME */
    BSL_CID_AT_STATEORPROVINCENAME = 163,    /* identifies STATEORPROVINCENAME */
    BSL_CID_AT_ORGANIZATIONNAME = 164,       /* identifies ORGANIZATIONNAME */
    BSL_CID_AT_ORGANIZATIONALUNITNAME = 165, /* identifies ORGANIZATIONALUNITNAME */
    BSL_CID_AT_TITLE = 166,                  /* identifies TITLE */
    BSL_CID_AT_DNQUALIFIER = 167,            /* identifies DNQUALIFIER */
    BSL_CID_AT_COUNTRYNAME = 168,            /* identifies COUNTRYNAME */
    BSL_CID_AT_SERIALNUMBER = 169,           /* identifies SERIALNUMBER */
    BSL_CID_AT_PSEUDONYM = 170,              /* identifies PSEUDONYM */
    BSL_CID_DOMAINCOMPONENT = 171,           /* identifies DOMAINCOMPONENT */
    BSL_CID_EMAILADDRESS = 172,              /* identifies EMAILADDRESS */
    /* PKIXIMPLICIT */
    BSL_CID_CE = 173,                            /* identifies CE */
    BSL_CID_CE_AUTHORITYKEYIDENTIFIER = 174,     /* identifies AUTHORITYKEYIDENTIFIER */
    BSL_CID_CE_SUBJECTKEYIDENTIFIER = 175,       /* identifies SUBJECTKEYIDENTIFIER */
    BSL_CID_CE_KEYUSAGE = 176,                   /* identifies KEYUSAGE */
    BSL_CID_CE_PRIVATEKEYUSAGEPERIOD = 177,      /* identifies PRIVATEKEYUSAGEPERIOD */
    BSL_CID_CE_CERTIFICATEPOLICIES = 178,        /* identifies CERTIFICATEPOLICIES */
    BSL_CID_ANYPOLICY = 179,                     /* identifies ANYPOLICY */
    BSL_CID_CE_POLICYMAPPINGS = 180,             /* identifies POLICYMAPPINGS */
    BSL_CID_CE_SUBJECTALTNAME = 181,             /* identifies SUBJECTALTNAME */
    BSL_CID_CE_ISSUERALTNAME = 182,              /* identifies ISSUERALTNAME */
    BSL_CID_CE_SUBJECTDIRECTORYATTRIBUTES = 183, /* identifies SUBJECTDIRECTORYATTRIBUTES */
    BSL_CID_CE_BASICCONSTRAINTS = 184,           /* identifies BASICCONSTRAINTS */
    BSL_CID_CE_NAMECONSTRAINTS = 185,            /* identifies NAMECONSTRAINTS */
    BSL_CID_CE_POLICYCONSTRAINTS = 186,          /* identifies POLICYCONSTRAINTS */
    BSL_CID_CE_CRLDISTRIBUTIONPOINTS = 187,      /* identifies CRLDISTRIBUTIONPOINTS */
    BSL_CID_CE_EXTKEYUSAGE = 188,                /* identifies EXTKEYUSAGE */
    BSL_CID_ANYEXTENDEDKEYUSAGE = 189,           /* identifies ANYEXTENDEDKEYUSAGE */
    BSL_CID_KP_SERVERAUTH = 190,                 /* identifies SERVERAUTH */
    BSL_CID_KP_CLIENTAUTH = 191,                 /* identifies CLIENTAUTH */
    BSL_CID_KP_CODESIGNING = 192,                /* identifies CODESIGNING */
    BSL_CID_KP_EMAILPROTECTION = 193,            /* identifies EMAILPROTECTION */
    BSL_CID_KP_TIMESTAMPING = 194,               /* identifies TIMESTAMPING */
    BSL_CID_KP_OCSPSIGNING = 195,                /* identifies OCSPSIGNING */
    BSL_CID_KP_IPSECIKE = 196,                   /* identifies IPSECIKE */
    BSL_CID_CE_INHIBITANYPOLICY = 197,           /* identifies INHIBITANYPOLICY */
    BSL_CID_CE_FRESHESTCRL = 198,                /* identifies FRESHESTCRL */
    BSL_CID_PE_AUTHORITYINFOACCESS = 199,        /* identifies AUTHORITYINFOACCESS */
    BSL_CID_PE_SUBJECTINFOACCESS = 200,          /* identifies SUBJECTINFOACCESS */
    BSL_CID_CE_CRLNUMBER = 201,                  /* identifies CRLNUMBER */
    BSL_CID_CE_ISSUINGDISTRIBUTIONPOINT = 202,   /* identifies ISSUINGDISTRIBUTIONPOINT */
    BSL_CID_CE_DELTACRLINDICATOR = 203,          /* identifies DELTACRLINDICATOR */
    BSL_CID_CE_CRLREASONS = 204,                 /* identifies CRLREASONS */
    BSL_CID_CE_CERTIFICATEISSUER = 205,          /* identifies CERTIFICATEISSUER */
    BSL_CID_CE_HOLDINSTRUCTIONCODE = 206,        /* identifies HOLDINSTRUCTIONCODE */
    BSL_CID_HOLDINSTRUCTION = 207,               /* identifies HOLDINSTRUCTION */
    BSL_CID_HOLDINSTRUCTION_NONE = 208,          /* identifies HOLDINSTRUCTION_NONE */
    BSL_CID_HOLDINSTRUCTION_CALLISSUER = 209,    /* identifies HOLDINSTRUCTION_CALLISSUER */
    BSL_CID_HOLDINSTRUCTION_REJECT = 210,        /* identifies HOLDINSTRUCTION_REJECT */
    BSL_CID_CE_INVALIDITYDATE = 211,             /* identifies INVALIDITYDATE */
    BSL_CID_PDA_DATEOFBIRTH = 212,               /* identifies DATEOFBIRTH */
    BSL_CID_PDA_PLACEOFBIRTH = 213,              /* identifies PLACEOFBIRTH */
    BSL_CID_PDA_GENDER = 214,                    /* identifies GENDER */
    BSL_CID_PDA_COUNTRYOFCITIZENSHIP = 215,      /* identifies COUNTRYOFCITIZENSHIP */
    BSL_CID_PDA_COUNTRYOFRESIDENCE = 216,        /* identifies COUNTRYOFRESIDENCE */
    BSL_CID_PDA = 217,                           /* identifies PDA */
    BSL_CID_ON_PERMANENTIDENTIFIER = 218,        /* identifies PERMANENTIDENTIFIER */
    BSL_CID_ON = 219,                            /* identifies ON */
    BSL_CID_CE_DOMAININFO = 220,                 /* identifies DOMAININFO */
    /* CMP */
    BSL_CID_PASSWORDBASEDMAC = 221, /* identifies PWD Based MAC */
    BSL_CID_DHBASEDMAC = 222,       /* identifies DH Based MAC */
    BSL_CID_IT = 223,               /* identifies IT */
    BSL_CID_CAPROTENCCERT = 224,    /* identifies CAPROTENCCERT */
    BSL_CID_SIGNKEYPAIRTYPES = 225, /* identifies Sign KeyPair Types */
    BSL_CID_ENCKEYPAIRTYPES = 226,  /* identifies KeyPair Types */
    BSL_CID_PREFERREDSYMMALG = 227, /* identifies Preferred Symmetric Algo */
    BSL_CID_CAKEYUPDATEINFO = 228,  /* identifies CA Key Update Info */
    BSL_CID_CURRENTCRL = 229,       /* identifies Current CRL */
    BSL_CID_CONFIRMWAITTIME = 230,  /* identifies ConfirmWaitTime */
    /* CRMF */
    BSL_CID_PKIP = 231,                       /* identifies PKIP */
    BSL_CID_REGCTRL = 232,                    /* identifies REGCTRL */
    BSL_CID_REGCTRL_REGTOKEN = 233,           /* identifies REGTOKEN */
    BSL_CID_REGCTRL_AUTHENTICATOR = 234,      /* identifies AUTHENTICATOR */
    BSL_CID_REGCTRL_PKIPUBLICATIONINFO = 235, /* identifies PKIPUBLICATIONINFO */
    BSL_CID_REGCTRL_PKIARCHIVEOPTIONS = 236,  /* identifies PKIARCHIVEOPTIONS */
    BSL_CID_REGCTRL_OLDCERTID = 237,          /* identifies OLDCERTID */
    BSL_CID_REGCTRL_PROTOCOLENCRKEY = 238,    /* identifies PROTOCOLENCRKEY */
    BSL_CID_REGINFO = 239,                    /* identifies REGINFO */
    BSL_CID_REGINFO_UTF8PAIRS = 240,          /* identifies UTF8PAIRS */
    BSL_CID_REGINFO_CERTREQ = 241,            /* identifies CERTREQ */
    /* PKCS12 */
    BSL_CID_PKCS12 = 242,                        /* identifies PKCS12 */
    BSL_CID_PKCS12PBEIDS = 243,                  /* identifies PKCS12 PBE */
    BSL_CID_PBE_SHAWITH128BITRC4 = 244,          /* identifies PBE Algo (SHAWITH128BITRC4) */
    BSL_CID_PBE_SHAWITH40BITRC4 = 245,           /* identifies PBE Algo (SHAWITH40BITRC4) */
    BSL_CID_PBE_SHAWITH3KEY_TRIPLE_DESCBC = 246, /* identifies PBE Algo (SHAWITH3KEY_TRIPLE_DESCBC) */
    BSL_CID_PBE_SHAWITH2KEY_TRIPLE_DESCBC = 247, /* identifies PBE Algo (SHAWITH2KEY_TRIPLE_DESCBC) */
    BSL_CID_PBE_SHAWITH128BIT_RC2CBC = 248,      /* identifies PBE Algo (SHAWITH128BIT_RC2CBC) */
    BSL_CID_PBE_SHAWITH40BIT_RC2CBC = 249, /* identifies PBE Algo (SHAWITH40BIT_RC2CBC) */
    BSL_CID_BAGTYPES = 250,                /* identifies Bag Types */
    BSL_CID_KEYBAG = 251,                  /* identifies Key Bag */
    BSL_CID_PKCS8SHROUDEDKEYBAG = 252,     /* identifies Bag Types */
    BSL_CID_CERTBAG = 253,                 /* identifies CERT Bag */
    BSL_CID_CRLBAG = 254,                  /* identifies CRL Bag */
    BSL_CID_SECRETBAG = 255,               /* identifies Secret Bag */
    BSL_CID_SAFECONTENTSBAG = 256,         /* identifies Safe Content Bag */
    BSL_CID_X509CERTIFICATE = 257,         /* identifies x509 Certificate */
    BSL_CID_SDSICERTIFICATE = 258,         /* identifies SDSI Certificate */
    BSL_CID_FRIENDLYNAME = 259,            /* identifies Freidnly Name */
    BSL_CID_LOCALKEYID = 260,              /* identifies Local Key ID */
    /* auth_frame */
    BSL_CID_CERTIFICATEREVOCATIONLIST = 261, /* identifies Certificate Revocation List */
    /* PKCS7 & 9 */
    BSL_CID_PKCS7 = 262,                      /* identifies PKCS7 */
    BSL_CID_PKCS7_SIMPLEDATA = 263,           /* identifies PKCS7 Simple Data */
    BSL_CID_PKCS7_SIGNEDDATA = 264,           /* identifies PKCS7 Signed Data */
    BSL_CID_PKCS7_ENVELOPEDDATA = 265,        /* identifies PKCS7 Enveloped Data */
    BSL_CID_PKCS7_SIGNED_ENVELOPEDDATA = 266, /* identifies PKCS7 Signed Enveloped Data */
    BSL_CID_PKCS7_DIGESTEDDATA = 267,         /* identifies PKCS7 Degested Data */
    BSL_CID_PKCS7_ENCRYPTEDDATA = 268,        /* identifies PKCS7 Encrypted Data */
    BSL_CID_PKCS9 = 269,                      /* identifies PKCS9 */
    BSL_CID_PKCS9_AT_CONTENTTYPE = 270,       /* identifies PKCS9 Content Type */
    BSL_CID_PKCS9_AT_MESSAGEDIGEST = 271,     /* identifies PKCS9 Message Digest */
    BSL_CID_PKCS9_AT_SIGNINGTIME = 272,       /* identifies PKCS9 Signing time */
    BSL_CID_PKCS9_AT_COUNTERSIGNATURE = 273,  /* identifies PKCS9 Counter Signature */
    BSL_CID_PKCS9_AT_RANDOMNONCE = 274,       /* identifies PKCS9 Signed Enveloped Data */
    BSL_CID_PKCS9_AT_SEQUENCENUMBER = 275,    /* identifies PKCS9 Sequence number */

    BSL_CID_MD4 = 276,       /* identifies MD4 hash algorithm */
    BSL_CID_HMAC_MD4 = 277,  /* identifies hmac with MD4 */
    BSL_CID_CMAC_AES = 278,  /* identifies CMAC-AES */
    BSL_CID_CMAC_TDES = 279, /* identifies CMAC-Triple DES */
    BSL_CID_RNG_HW = 280,    /* identifies TRNG */
    BSL_CID_RNG_SW = 281,    /* identifies PRNG */
    BSL_CID_XCBC_AES = 282,  /* identifies XCBC-MAC-AES */
    BSL_CID_RC2_ECB = 283,   /* identifies RC2 algorithm in ECB mode */
    BSL_CID_RC2_CBC = 284,   /* identifies RC2 algorithm in CBC mode */
    BSL_CID_RC2_OFB = 285,   /* identifies RC2 algorithm in OFB mode */
    BSL_CID_RC2_CFB = 286,   /* identifies RC2 algorithm in CFB mode */

    BSL_CID_MD5_SHA1 = 287,

    BSL_CID_SECP384R1 = 288,         /* identifies NIST prime curve 384 */
    BSL_CID_SECP521R1 = 289,         /* identifies NIST prime curve 521 */
    BSL_CID_SM3 = 290,               /* identifies SM3 hash algorithm */
    BSL_CID_HMAC_SM3 = 291,          /* identifies hmac with SM3 */
    BSL_CID_SM2DSAWITHSM3 = 292,     /* identifies BSL_CID_SM2DSAWITHSM3 */
    BSL_CID_SM2DSAWITHSHA1 = 293,    /* identifies BSL_CID_SM2DSAWITHSHA1 */
    BSL_CID_SM2DSAWITHSHA256 = 294,  /* identifies BSL_CID_SM2DSAWITHSHA256 */
    BSL_CID_SM2PRIME256 = 295,       /* identifies BSL_CID_PRIME256SM2 */
    BSL_CID_SM2DSA = 296,            /* identifies SM2 DSA */
    BSL_CID_SM2KEP = 297,            /* BSL_CID_SM2KEP */
    BSL_CID_SM2PKEA = 298,           /* BSL_CID_SM2PKEA */
    BSL_CID_AES128_GCM = 299,        /* Identifies the AES128 algorithm in GCM mode */
    BSL_CID_AES192_GCM = 300,        /* Identifies the AES128 algorithm in GCM mode */
    BSL_CID_AES256_GCM = 301,        /* Identifies the AES256 algorithm in GCM mode */
    BSL_CID_AES128_CTR = 302,        /* Identifies the AES128 algorithm in CTR mode */
    BSL_CID_AES192_CTR = 303,        /* Identifies the AES128 algorithm in CTR mode */
    BSL_CID_AES256_CTR = 304,        /* Identifies the AES128 algorithm in CTR mode */
    BSL_CID_UNSTRUCTURED_NAME = 305, /* identifies unstructuredName */
    BSL_CID_UNSTRUCTURED_ADDR = 306, /* identifies unstructuredAddress */
    BSL_CID_BF_ECB = 307,            /* Identifies the Blowfish algorithm in ECB mode */
    BSL_CID_BF_CBC = 308,            /* Identifies the Blowfish algorithm in CBC mode */
    BSL_CID_BF_CFB = 309,            /* Identifies the Blowfish algorithm in CFB mode */
    BSL_CID_BF_OFB = 310,            /* Identifies the Blowfish algorithm in OFB mode */
    BSL_CID_AES128_CCM = 311,
    BSL_CID_AES192_CCM = 312,
    BSL_CID_AES256_CCM = 313,

    BSL_CID_AT_STREETADDRESS = 314,       /* Identifies the streetAddress in EV certs */
    BSL_CID_AT_BUSINESSCATEGORY = 315,    /* Identifies the businessCategory in EV certs */
    BSL_CID_AT_POSTALCODE = 316,          /* Identifies the postalCode in EV certs */
    BSL_CID_JD_LOCALITYNAME = 317,        /* Identifies the streetAddress in EV certs */
    BSL_CID_JD_STATEORPROVINCENAME = 318, /* Identifies the jurisdictionLocalityName in EV certs */
    BSL_CID_JD_COUNTRYNAME = 319,         /* Identifies the jurisdictionCountryName in EV certs */
    BSL_CID_HMAC_SHA1_DIGEST = 320,

    BSL_CID_NIST_PRIME224 = 321,  /* NIST Curve P-224 */
    BSL_CID_NIST_C2PNB163K = 322, /* NIST Binary Curve 163K */
    BSL_CID_NIST_C2PNB163B = 323, /* NIST Binary Curve 163B */
    BSL_CID_NIST_C2TNB233K = 324, /* NIST Binary Curve 233K */
    BSL_CID_NIST_C2TNB233B = 325, /* NIST Binary Curve 233B */
    BSL_CID_NIST_C2PNB283K = 326, /* NIST Binary Curve 283K */
    BSL_CID_NIST_C2PNB283B = 327, /* NIST Binary Curve 283B */
    BSL_CID_NIST_C2TNB409K = 328, /* NIST Binary Curve 409K */
    BSL_CID_NIST_C2TNB409B = 329, /* NIST Binary Curve 409B */
    BSL_CID_NIST_C2PNB571K = 330, /* NIST Binary Curve 571K */
    BSL_CID_NIST_C2PNB571B = 331, /* NIST Binary Curve 571B */
    BSL_CID_PBE_HMACSHA512WITHAES256_CBC = 332,

    BSL_CID_CE_SKAE = 333,   /* Identifies SKAE extension */
    BSL_CID_ED25519 = 334,   /* Identifies ED25519 algorithm */
    BSL_CID_X25519 = 335,    /* Identifies X25519 algorithm */
    BSL_CID_RSASSAPSS = 336, /* Identifies RSASSAPSS algorithm */
    BSL_CID_MGF1 = 337,      /* Identifies MaskGen algorithm */

    BSL_CID_SCRYPT = 338,    /* Identifieds Scrypt KDF algorithm */
    BSL_CID_PBES1 = 339,     /* Identifieds PBES1 KDF algorithm */
    BSL_CID_KDF2 = 340,      /* Identifieds KDF2 KDF algorithm */
    BSL_CID_DOT16KDF = 341,  /* Identifieds dot16 KDF algorithm */

    BSL_CID_SM4 = 342,        /* Identifieds SM4 algorithm */
    BSL_CID_SM4_ECB = 343,    /* Identifieds SM4 ECB algorithm */
    BSL_CID_SM4_CBC = 344,    /* Identifieds SM4 CBC algorithm */
    BSL_CID_KWRAP_AES = 345,  /* Identifieds AES KWRAP algorithm */
    BSL_CID_KWRAP_SM4 = 346,  /* Identifieds SM4 KWRAP algorithm */
    BSL_CID_CMAC_SM4 = 347,   /* identifies CMAC SM4 */

    BSL_CID_SM3WITHRSAENCRYPTION = 348,  /* identifies signature using SM3 and RSA */
    BSL_CID_HARDWAREMODULENAME = 349,
    BSL_CID_AT_DESCRIPTION = 350,

    BSL_CID_DECODE_UNKNOWN = 1000,

    BSL_CID_HMAC_SHA3_224 = 2000,        /* identifies hmac with SHA3_224 */
    BSL_CID_HMAC_SHA3_256 = 2001,        /* identifies hmac with SHA3_256 */
    BSL_CID_HMAC_SHA3_384 = 2002,        /* identifies hmac with SHA3_384 */
    BSL_CID_HMAC_SHA3_512 = 2003,        /* identifies hmac with SHA3_512 */

    BSL_CID_DSAWITHSHA256 = 2004,        /* identifies signature using SHA256 and DSA */
    BSL_CID_DSAWITHSHA224 = 2005,        /* identifies signature using SHA224 and DSA */
    BSL_CID_DSAWITHSHA384 = 2006,        /* identifies signature using SHA384 and DSA */
    BSL_CID_DSAWITHSHA512 = 2007,        /* identifies signature using SHA512 and DSA */
    BSL_CID_SHA224WITHRSAENCRYPTION = 2008, /* identifies signature using SHA224 and RSA */

    BSL_CID_SHA3_224 = 2009,
    BSL_CID_SHA3_256 = 2010,
    BSL_CID_SHA3_384 = 2011,
    BSL_CID_SHA3_512 = 2012,
    BSL_CID_SHAKE128 = 2013,
    BSL_CID_SHAKE256 = 2014,

    BSL_CID_HMAC_MD5_SHA1 = 2015,
    BSL_CID_CMAC_AES128 = 2016,
    BSL_CID_CMAC_AES192 = 2017,
    BSL_CID_CMAC_AES256 = 2018,
    BSL_CID_GMAC_AES128 = 2019,
    BSL_CID_GMAC_AES192 = 2020,
    BSL_CID_GMAC_AES256 = 2021,

    BSL_CID_AES128_XTS = 2022,
    BSL_CID_AES256_XTS = 2023,
    BSL_CID_AES128_WRAP_NOPAD = 2024,
    BSL_CID_AES192_WRAP_NOPAD = 2025,
    BSL_CID_AES256_WRAP_NOPAD = 2026,
    BSL_CID_AES128_WRAP_PAD = 2027,
    BSL_CID_AES192_WRAP_PAD = 2028,
    BSL_CID_AES256_WRAP_PAD = 2029,
    BSL_CID_CHACHA20_POLY1305 = 2030,
    BSL_CID_SM4_XTS = 2031,
    BSL_CID_SM4_CTR = 2032,
    BSL_CID_SM4_GCM = 2033,
    BSL_CID_SM4_CFB = 2034,
    BSL_CID_SM4_OFB = 2035,

    BSL_CID_KDFTLS12 = 2036,
    BSL_CID_HKDF = 2037,

    BSL_CID_RAND_SHA1 = 2038,
    BSL_CID_RAND_SHA224 = 2039,
    BSL_CID_RAND_SHA256 = 2040,
    BSL_CID_RAND_SHA384 = 2041,
    BSL_CID_RAND_SHA512 = 2042,
    BSL_CID_RAND_SM3 = 2043,
    BSL_CID_RAND_HMAC_SHA1 = 2044,
    BSL_CID_RAND_HMAC_SHA224 = 2045,
    BSL_CID_RAND_HMAC_SHA256 = 2046,
    BSL_CID_RAND_HMAC_SHA384 = 2047,
    BSL_CID_RAND_HMAC_SHA512 = 2048,
    BSL_CID_RAND_AES128_CTR = 2049,
    BSL_CID_RAND_AES192_CTR = 2050,
    BSL_CID_RAND_AES256_CTR = 2051,
    BSL_CID_RAND_AES128_CTR_DF = 2052,
    BSL_CID_RAND_AES192_CTR_DF = 2053,
    BSL_CID_RAND_AES256_CTR_DF = 2054,
    BSL_CID_RAND_SM4_CTR_DF = 2055,

    BSL_CID_ED448 = 2056,
    BSL_CID_X448 = 2057,

    BSL_CID_DH_RFC2409_768 = 2060,
    BSL_CID_DH_RFC2409_1024 = 2061,
    BSL_CID_DH_RFC3526_1536 = 2062,
    BSL_CID_DH_RFC3526_2048 = 2063,
    BSL_CID_DH_RFC3526_3072 = 2064,
    BSL_CID_DH_RFC3526_4096 = 2065,
    BSL_CID_DH_RFC3526_6144 = 2066,
    BSL_CID_DH_RFC3526_8192 = 2067,
    BSL_CID_DH_RFC7919_2048 = 2068,
    BSL_CID_DH_RFC7919_3072 = 2069,
    BSL_CID_DH_RFC7919_4096 = 2070,
    BSL_CID_DH_RFC7919_6144 = 2071,
    BSL_CID_DH_RFC7919_8192 = 2072,
    BSL_CID_ECC_BRAINPOOLP256R1 = 2073,
    BSL_CID_ECC_BRAINPOOLP384R1 = 2074,
    BSL_CID_ECC_BRAINPOOLP512R1 = 2075,
    BSL_CID_SIPHASH64 = 2076,
    BSL_CID_SIPHASH128 = 2077,

    // Netscape
    BSL_CID_NETSCAPE = 2078,
    BSL_CID_NS_CERTEXT = 2079,
    BSL_CID_NS_DATATYPE = 2080,
    BSL_CID_NS_CERTTYPE = 2081,
    BSL_CID_NS_BASEURL = 2082,
    BSL_CID_NS_REVOCATIOPNURL = 2083,
    BSL_CID_NS_CAREVOCATIONURL = 2084,
    BSL_CID_NS_RENEWALURL = 2085,
    BSL_CID_NS_CAPOLICYURL = 2086,
    BSL_CID_NS_SSLSERVERNAME = 2087,
    BSL_CID_NS_COMMENT = 2088,
    BSL_CID_NS_CERTSEQUENCE = 2089,
    BSL_CID_NS_SGC = 2090,

    BSL_CID_EC192WAPI = 2091,
    BSL_CID_CBC_MAC_SM4 = 2092,
    BSL_CID_EC_PUBLICKEY = 2093,  /* identifies EC_PUBLICKEY */

    BSL_CID_AT_USERID = 2094,

    BSL_CID_PKCS7_CONTENTINFO = 2095,
    BSL_CID_PKCS12KDF = 2096,

    BSL_CID_ML_KEM = 2100,
    BSL_CID_ML_DSA = 2101,
    BSL_CID_HYBRID_KEM = 2102,
    BSL_CID_X25519_MLKEM512 = 2103,
    BSL_CID_X25519_MLKEM768 = 2104,
    BSL_CID_X25519_MLKEM1024 = 2105,
    BSL_CID_X448_MLKEM512 = 2106,
    BSL_CID_X448_MLKEM768 = 2107,
    BSL_CID_X448_MLKEM1024 = 2108,
    BSL_CID_ECDH_NISTP256_MLKEM512 = 2109,
    BSL_CID_ECDH_NISTP256_MLKEM768 = 2110,
    BSL_CID_ECDH_NISTP256_MLKEM1024 = 2111,
    BSL_CID_ECDH_NISTP384_MLKEM512 = 2112,
    BSL_CID_ECDH_NISTP384_MLKEM768 = 2113,
    BSL_CID_ECDH_NISTP384_MLKEM1024 = 2114,
    BSL_CID_ECDH_NISTP521_MLKEM512 = 2115,
    BSL_CID_ECDH_NISTP521_MLKEM768 = 2116,
    BSL_CID_ECDH_NISTP521_MLKEM1024 = 2117,

    BSL_CID_SM9 = 5201,
    BSL_CID_ECC_SM9 = 5202,
    BSL_CID_PAILLIER = 5203,
    BSL_CID_ELGAMAL = 5204,
    BSL_CID_SLH_DSA = 5205,         /**< Identifies SLH-DSA algorithm */
    BSL_CID_SPAKE2P = 5206,         /**< Identifies SPAKE2+ algorithm */
    BSL_CID_SPAKE2P_PARAMS = 5207,  /**< Identifies SPAKE2+ parameters */

    BSL_CID_MAC_AEAD = 5300,

    BSL_CID_AES128_CCM8,
    BSL_CID_AES256_CCM8,

    BSL_CID_MAX,
    BSL_CID_EXTEND = 0x60000000,
} BslCid;

typedef struct {
    uint32_t octetLen;
    char *octs;
    uint32_t flags;
} BslOidString;

/**
 * @ingroup bsl_obj
 * @brief Create an object identifier mapping
 * @param[in] oid The object identifier string
 * @param[in] oidName The name of the object identifier
 * @param[in] cid The algorithm ID to map to
 * @return HITLS_OK on success, error code on failure
 */
int32_t BSL_OBJ_Create(const BslOidString *oid, const char *oidName, int32_t cid);


/**
 * @ingroup bsl_obj
 * @brief Create a signature algorithm ID mapping
 * @param[in] signId The signature algorithm ID
 * @param[in] asymId The asymmetric algorithm ID
 * @param[in] hashId The hash algorithm ID
 * @return HITLS_OK on success, error code on failure
 */
int32_t BSL_OBJ_CreateSignId(int32_t signId, int32_t asymId, int32_t hashId);

/**
 * @ingroup bsl_obj
 * @brief Get the object identifier string from the algorithm ID
 * @param[in] inputCid The algorithm ID
 * @return The object identifier string
 */
BslOidString *BSL_OBJ_GetOidFromCID(BslCid inputCid);

/**
 * @ingroup bsl_obj
 * @brief Get the algorithm ID from the object identifier string
 * @param[in] oid The object identifier string
 * @return The algorithm ID
 */
BslCid BSL_OBJ_GetCIDFromOid(BslOidString *oid);

#ifdef __cplusplus
}
#endif

#endif // BSL_OBJ_H
