/* Copyright (c) 2025，Shandong University — School of Cyber Science and Technology
* Contributor: Mingzhang Sun
 * Instructor:  Weijia Wang
*/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "bsl_pem_internal.h"
#include "app_opt.h"
#include "app_function.h"
#include "app_list.h"
#include "app_errno.h"
#include "app_help.h"
#include "app_print.h"
#include "app_asn1parse.h"

/* Safety caps */
#define MAX_TAG_BYTES (8)
#define MAX_LEN_BYTES (8)
#define MAX_PEM_READ (16 * 1024 * 1024)

/* ASN.1 Tag encoding constants */
#define ASN1_TAG_LONG_FORM_MASK (0x1F)
#define ASN1_TAG_CLASS_MASK (0x3)
#define ASN1_TAG_CLASS_SHIFT (6)
#define ASN1_TAG_CONSTRUCTED_MASK (0x01)
#define ASN1_TAG_CONSTRUCTED_SHIFT (5)
#define ASN1_LENGTH_LONG_FORM_MASK (0x80)
#define ASN1_LENGTH_OCTETS_MASK (0x7F)
#define ASN1_TAG_CONTINUATION_BIT (0x80)
#define ASN1_TAG_DATA_BITS_MASK (0x7F)

/* ASN.1 Tag Class values */
#define ASN1_CLASS_UNIVERSAL (0)
#define ASN1_CLASS_APPLICATION (1)
#define ASN1_CLASS_CONTEXT (2)
#define ASN1_CLASS_PRIVATE (3)

/* ASN.1 Universal Tag Numbers */
#define ASN1_TAG_EOC (0)
#define ASN1_TAG_BOOLEAN (1)
#define ASN1_TAG_INTEGER (2)
#define ASN1_TAG_BIT_STRING (3)
#define ASN1_TAG_OCTET_STRING (4)
#define ASN1_TAG_NULL (5)
#define ASN1_TAG_OBJECT_IDENTIFIER (6)
#define ASN1_TAG_UTF8STRING (12)
#define ASN1_TAG_SEQUENCE (16)
#define ASN1_TAG_SET (17)
#define ASN1_TAG_PRINTABLESTRING (19)
#define ASN1_TAG_IA5STRING (22)
#define ASN1_TAG_UTCTIME (23)
#define ASN1_TAG_GENERALIZEDTIME (24)

/* Character range constants */
#define ASCII_PRINTABLE_MIN (0x20)
#define ASCII_PRINTABLE_MAX (0x7E)

/* OID encoding constants */
#define OID_FIRST_BYTE_DIVISOR (40)
#define OID_ARC_SIZE (40)
#define OID_MAX_NODES (64)
#define MAX_OID_NODES (64)
#define MAX_OID_BYTES_PER_ARC (9)

/* Buffer size constants */
#define TYPEBUF_SIZE (128)
#define OID_TMP_BUFFER_SIZE (512)
#define HEXBUF_SIZE (1024)

/* Display limits */
#define MAX_VALUE_DISPLAY_BYTES (32)
#define MAX_OID_HEX_DISPLAY_BYTES (256)
#define HEX_DUMP_BYTES_PER_LINE (16)

/* Bit shift constants */
#define BITS_PER_BYTE (8)
#define BITS_PER_OCTET_7 (7)

/* Hex formatting constants */
#define HEX_CHARS_PER_BYTE (2)
#define HEX_SAFETY_MARGIN (4)

/* Minimum BER/DER header size */
#define MIN_BER_HEADER_SIZE (2)

/* Maximum recursion depth to guard against stack exhaustion */
#define MAX_PARSE_DEPTH (128)

/* Option types for asn1parse command */
typedef enum {
    OPT_ASN1PARSE_UNK = -1,
    OPT_ASN1PARSE_EOF = 0,
    OPT_ASN1PARSE_IN,
    OPT_ASN1PARSE_INDENT,
    OPT_ASN1PARSE_DUMP,
    OPT_ASN1PARSE_NOOUT,
    OPT_ASN1PARSE_OUT,
    OPT_ASN1PARSE_INFORM,
    OPT_ASN1PARSE_STRPARSE,
    OPT_ASN1PARSE_HELP
} Asn1ParseOptType;

static const HITLS_CmdOption asn1_cmd_options[] = {
    {"in",         OPT_ASN1PARSE_IN,       HITLS_APP_OPT_VALUETYPE_IN_FILE,   "Input file"},
    {"i",          OPT_ASN1PARSE_INDENT,   HITLS_APP_OPT_VALUETYPE_NO_VALUE,  "Indent output"},
    {"dump",       OPT_ASN1PARSE_DUMP,     HITLS_APP_OPT_VALUETYPE_NO_VALUE,  "Hex+ASCII dump of extracted TLV"},
    {"noout",      OPT_ASN1PARSE_NOOUT,    HITLS_APP_OPT_VALUETYPE_NO_VALUE,  "Do not print values"},
    {"out",        OPT_ASN1PARSE_OUT,      HITLS_APP_OPT_VALUETYPE_OUT_FILE,  "Output file for -strparse (value only)"},
    {"inform",     OPT_ASN1PARSE_INFORM,   HITLS_APP_OPT_VALUETYPE_FMT_PEMDER, "Input format: PEM or DER"},
    {"strparse",   OPT_ASN1PARSE_STRPARSE, HITLS_APP_OPT_VALUETYPE_LONG,      "Parse at offset (decimal)"},
    {"help",       OPT_ASN1PARSE_HELP,     HITLS_APP_OPT_VALUETYPE_NO_VALUE,  "Display help"},
    {NULL, 0, 0, NULL}
};

typedef struct {
    const char *oid;
    const char *name;
} OID_MAP_ENTRY;

static const OID_MAP_ENTRY OID_MAP[] = {
    {"1.2.840.113549.1.1.1", "rsaEncryption"},
    {"1.2.840.113549.1.1.2", "md2WithRSAEncryption"},
    {"1.2.840.113549.1.1.4", "md5WithRSAEncryption"},
    {"1.2.840.113549.1.1.5", "sha1WithRSAEncryption"},
    {"1.2.840.113549.1.1.11", "sha256WithRSAEncryption"},
    {"1.2.840.113549.1.1.12", "sha384WithRSAEncryption"},
    {"1.2.840.113549.1.1.13", "sha512WithRSAEncryption"},
    {"1.2.840.10045.2.1", "ecPublicKey"},
    {"1.2.840.10045.3.1.7", "prime256v1"},
    {"1.3.132.0.34", "secp384r1"},
    {"1.3.132.0.35", "secp521r1"},
    {"1.3.14.3.2.26", "sha1"},
    {"2.16.840.1.101.3.4.2.1", "sha256"},
    {"2.16.840.1.101.3.4.2.2", "sha384"},
    {"2.16.840.1.101.3.4.2.3", "sha512"},
    {"2.5.4.3", "commonName"},
    {"2.5.4.6", "countryName"},
    {"2.5.4.7", "localityName"},
    {"2.5.4.8", "stateOrProvinceName"},
    {"2.5.4.10", "organizationName"},
    {"2.5.4.11", "organizationalUnitName"},
    {"2.5.29.14", "subjectKeyIdentifier"},
    {"2.5.29.15", "keyUsage"},
    {"2.5.29.17", "subjectAltName"},
    {"2.5.29.19", "basicConstraints"},
    {"2.5.29.35", "authorityKeyIdentifier"},
    {"2.5.29.37", "extKeyUsage"},
    {"1.3.6.1.5.5.7.3.1", "serverAuth"},
    {"1.3.6.1.5.5.7.3.2", "clientAuth"},
    {"1.3.6.1.5.5.7.1.1", "authorityInfoAccess"},
    {"1.3.6.1.5.5.7.48.1", "ocsp"},
    {"1.3.6.1.5.5.7.48.2", "caIssuers"},
    {"2.5.29.31", "cRLDistributionPoints"},
    {"1.2.840.113549.1.1.10", "rsassaPss"},
    {"1.2.840.113549.1.9.1", "emailAddress"},
    {"1.2.840.113549.1.7.1", "data"},
    {"2.5.4.5", "serialNumber"},
    {"2.5.29.20", "cRLNumber"},
    {"2.5.29.21", "reasonCode"},
    {"2.5.29.32", "certificatePolicies"},
    {"2.5.29.46", "freshestCRL"},
    {"1.2.840.10045.4.3.2", "ecdsa-with-SHA256"},
    {"1.2.840.10045.4.3.3", "ecdsa-with-SHA384"},
    {"1.2.840.10045.4.3.4", "ecdsa-with-SHA512"},
    {"1.2.156.10197.1.301", "sm2p256v1"},
    {"1.2.840.113549.1.1.14", "sha224WithRSAEncryption"},
    {"1.3.6.1.5.5.7.3.3", "codeSigning"},
    {"1.3.6.1.5.5.7.3.4", "emailProtection"},
    {"1.2.840.113549.2.5", "md5"},
    {"1.2.840.113549.2.2", "md2"},
    {"1.2.840.10040.4.3", "dsaWithSHA1"},
    {"1.2.840.113549.1.12.10.1.2", "pbeWithSHA1AndDES-CBC"},
    {"1.2.840.10045.4.1", "ecdsa-with-SHA1"},
    {NULL, NULL}
};

static int ReadFileToBuf(const char *filename, uint8_t **outBuf, size_t *outLen, size_t maxAllowed)
{
    if (!outBuf || !outLen) {
        return HITLS_APP_INVALID_ARG;
    }
    *outBuf = NULL;
    *outLen = 0;

    BSL_UIO *uio = HITLS_APP_UioOpen(filename, 'r', filename != NULL ? 1 : 0);
    if (uio == NULL) {
        AppPrintError("Failed to open input: %s\n", filename ? filename : "stdin");
        return HITLS_APP_UIO_FAIL;
    }
    uint64_t readLen = 0;
    int32_t rc = HITLS_APP_OptReadUio(uio, outBuf, &readLen, maxAllowed);
    BSL_UIO_Free(uio);
    if (rc != HITLS_APP_SUCCESS) {
        return HITLS_APP_UIO_FAIL;
    }
    if (readLen > SIZE_MAX) {
        BSL_SAL_FREE(*outBuf);
        *outBuf = NULL;
        AppPrintError("File too large for this platform\n");
        return HITLS_APP_INTERNAL_EXCEPTION;
    }
    *outLen = (size_t)readLen;
    return HITLS_APP_SUCCESS;
}

typedef struct {
    unsigned int tagClass;
    bool constructed;
    unsigned long long tagNumber;
    size_t tagBytes;
} Asn1TagInfo;

static int ReadTag(const uint8_t *buf, size_t bufLen, size_t off, Asn1TagInfo *tagInfo)
{
    if (!buf || !tagInfo || off >= bufLen) {
        return HITLS_APP_INVALID_ARG;
    }
    uint8_t b = buf[off];
    tagInfo->tagClass = (b >> ASN1_TAG_CLASS_SHIFT) & ASN1_TAG_CLASS_MASK;
    tagInfo->constructed = ((b >> ASN1_TAG_CONSTRUCTED_SHIFT) & ASN1_TAG_CONSTRUCTED_MASK) ? true : false;
    unsigned int t = b & ASN1_TAG_LONG_FORM_MASK;
    tagInfo->tagBytes = 1;
    tagInfo->tagNumber = 0;
    if (t != ASN1_TAG_LONG_FORM_MASK) {
        tagInfo->tagNumber = t;
        return HITLS_APP_SUCCESS;
    } else {
        tagInfo->tagNumber = 0;
        while (tagInfo->tagBytes < MAX_TAG_BYTES && (off + tagInfo->tagBytes) < bufLen) {
            uint8_t byte = buf[off + tagInfo->tagBytes];
            tagInfo->tagBytes++;
            tagInfo->tagNumber = (tagInfo->tagNumber << BITS_PER_OCTET_7) | (byte & ASN1_TAG_DATA_BITS_MASK);
            if (!(byte & ASN1_TAG_CONTINUATION_BIT)) {
                return HITLS_APP_SUCCESS;
            }
        }
    }
    return HITLS_APP_DECODE_FAIL;
}

static int ReadLength(const uint8_t *buf, size_t bufLen, size_t off, size_t *lenLen, size_t *contentLen)
{
    if (!buf || !lenLen || !contentLen || off >= bufLen) {
        return HITLS_APP_INVALID_ARG;
    }
    uint8_t b = buf[off];
    if ((b & ASN1_LENGTH_LONG_FORM_MASK) == 0) {
        *lenLen = 1;
        *contentLen = b;
        return HITLS_APP_SUCCESS;
    }
    unsigned int n = b & ASN1_LENGTH_OCTETS_MASK;
    if (n == 0 || n > MAX_LEN_BYTES) {
        return HITLS_APP_DECODE_FAIL;
    }
    if (off + 1 + n > bufLen) {
        return HITLS_APP_DECODE_FAIL;
    }
    size_t v = 0;
    for (unsigned int i = 0; i < n; i++) {
        uint8_t byte = buf[off + 1 + i];
        if (v > (SIZE_MAX >> BITS_PER_BYTE)) {
            return HITLS_APP_DECODE_FAIL;
        }
        v = (v << BITS_PER_BYTE) | byte;
    }
    *lenLen = 1 + n;
    *contentLen = v;
    return HITLS_APP_SUCCESS;
}

static bool ParseOidArc(const uint8_t *buf, size_t endPos, size_t *pos, unsigned long long *arcValue)
{
    unsigned long long val = 0;
    size_t bytes = 0;
    size_t i = *pos;

    while (i < endPos && bytes < MAX_OID_BYTES_PER_ARC) {
        uint8_t b = buf[i++];
        val = (val << BITS_PER_OCTET_7) | (b & ASN1_TAG_DATA_BITS_MASK);
        bytes++;
        if (!(b & ASN1_TAG_CONTINUATION_BIT)) {
            *arcValue = val;
            *pos = i;
            return true;
        }
    }
    return false;
}

static bool ParseOidFirstArc(const uint8_t *buf, size_t endPos, size_t *pos,
    unsigned long long *nodes, size_t *nodeCount)
{
    unsigned long long first = 0;
    if (!ParseOidArc(buf, endPos, pos, &first)) {
        return false;
    }
    if (first < 2 * OID_ARC_SIZE) {
        nodes[(*nodeCount)++] = first / OID_ARC_SIZE;
        nodes[(*nodeCount)++] = first % OID_ARC_SIZE;
    } else {
        nodes[(*nodeCount)++] = 2;
        nodes[(*nodeCount)++] = first - 2 * OID_ARC_SIZE;
    }
    return true;
}

/* OID parsing context */
typedef struct {
    const uint8_t *buf;
    size_t bufLen;
    size_t off;
    size_t len;
} OidParseContext;

static size_t ParseOidNodes(const OidParseContext *ctx, unsigned long long *nodes, size_t maxNodes)
{
    if (!ctx || !ctx->buf || !nodes || ctx->len == 0 || maxNodes == 0) {
        return 0;
    }
    if (ctx->off >= ctx->bufLen || ctx->off > SIZE_MAX - ctx->len || ctx->off + ctx->len > ctx->bufLen) {
        return 0;
    }

    size_t nn = 0;
    size_t i = ctx->off;
    size_t endPos = ctx->off + ctx->len;
    if (!ParseOidFirstArc(ctx->buf, endPos, &i, nodes, &nn)) {
        return 0;
    }
    while (i < endPos && nn < maxNodes) {
        unsigned long long arcValue = 0;
        if (!ParseOidArc(ctx->buf, endPos, &i, &arcValue)) {
            break;
        }
        nodes[nn++] = arcValue;
    }
    return nn;
}

static char *OidBytesToDottedAlloc(const uint8_t *buf, size_t bufLen, size_t off, size_t len)
{
    if (!buf || len == 0) {
        return NULL;
    }
    if (off >= bufLen || len > bufLen - off) {
        return NULL;
    }
    unsigned long long nodes[MAX_OID_NODES];
    OidParseContext ctx = {
        .buf = buf,
        .bufLen = bufLen,
        .off = off,
        .len = len
    };
    size_t nn = ParseOidNodes(&ctx, nodes, MAX_OID_NODES);
    if (nn == 0) {
        return NULL;
    }

    char tmp[OID_TMP_BUFFER_SIZE];
    size_t pos = 0;
    for (size_t i = 0; i < nn; i++) {
        size_t remaining = sizeof(tmp) > pos ? sizeof(tmp) - pos : 0;
        int written = 0;
        if (i == 0) {
            written = snprintf(tmp + pos, remaining, "%llu", (unsigned long long)nodes[i]);
        } else {
            written = snprintf(tmp + pos, remaining, ".%llu", (unsigned long long)nodes[i]);
        }
        if (written < 0) {
            break;
        }
        pos += (size_t)written;
        if (pos + MAX_VALUE_DISPLAY_BYTES >= sizeof(tmp)) {
            break;
        }
    }

    char *out = (char *)BSL_SAL_Calloc(pos + 1, 1);
    if (!out) {
        return NULL;
    }
    memcpy(out, tmp, pos);
    out[pos] = '\0';
    return out;
}

static const char *OidLookupName(const char *dotted)
{
    if (!dotted) {
        return NULL;
    }
    for (size_t i = 0; OID_MAP[i].oid != NULL; i++) {
        if (strcmp(OID_MAP[i].oid, dotted) == 0) {
            return OID_MAP[i].name;
        }
    }
    return NULL;
}

static void TagToNameStr(unsigned int tagClass, unsigned long long tagNumber, char *out, size_t outlen)
{
    if (tagClass == ASN1_CLASS_UNIVERSAL) {
        switch ((unsigned int)tagNumber) {
            case ASN1_TAG_EOC: (void)snprintf(out, outlen, "EOC"); return;
            case ASN1_TAG_BOOLEAN: (void)snprintf(out, outlen, "BOOLEAN"); return;
            case ASN1_TAG_INTEGER: (void)snprintf(out, outlen, "INTEGER"); return;
            case ASN1_TAG_BIT_STRING: (void)snprintf(out, outlen, "BIT STRING"); return;
            case ASN1_TAG_OCTET_STRING: (void)snprintf(out, outlen, "OCTET STRING"); return;
            case ASN1_TAG_NULL: (void)snprintf(out, outlen, "NULL"); return;
            case ASN1_TAG_OBJECT_IDENTIFIER: (void)snprintf(out, outlen, "OBJECT"); return;
            case ASN1_TAG_UTF8STRING: (void)snprintf(out, outlen, "UTF8STRING"); return;
            case ASN1_TAG_SEQUENCE: (void)snprintf(out, outlen, "SEQUENCE"); return;
            case ASN1_TAG_SET: (void)snprintf(out, outlen, "SET"); return;
            case ASN1_TAG_PRINTABLESTRING: (void)snprintf(out, outlen, "PRINTABLESTRING"); return;
            case ASN1_TAG_IA5STRING: (void)snprintf(out, outlen, "IA5STRING"); return;
            case ASN1_TAG_UTCTIME: (void)snprintf(out, outlen, "UTCTIME"); return;
            case ASN1_TAG_GENERALIZEDTIME: (void)snprintf(out, outlen, "GENERALIZEDTIME"); return;
            default: (void)snprintf(out, outlen, "UNIVERSAL(%llu)", tagNumber); return;
        }
    } else if (tagClass == ASN1_CLASS_APPLICATION) {
        (void)snprintf(out, outlen, "[%llu] APPLICATION", tagNumber);
    } else if (tagClass == ASN1_CLASS_CONTEXT) {
        (void)snprintf(out, outlen, "%llu", tagNumber);
    } else {
        (void)snprintf(out, outlen, "[%llu] PRIVATE", tagNumber);
    }
}

static void PrintOidValue(const uint8_t *buf, size_t bufLen, size_t valOff, size_t contentLen)
{
    if (valOff >= bufLen || contentLen > bufLen - valOff) {
        printf("\n");
        return;
    }

    char *dotted = OidBytesToDottedAlloc(buf, bufLen, valOff, contentLen);
    size_t show = contentLen;
    if (show > MAX_OID_HEX_DISPLAY_BYTES) {
        show = MAX_OID_HEX_DISPLAY_BYTES;
    }
    char hexbuf[HEXBUF_SIZE];
    size_t hexpos = 0;
    for (size_t i = 0; i < show && i < sizeof(hexbuf) / HEX_CHARS_PER_BYTE; i++) {
        size_t remaining = sizeof(hexbuf) - hexpos;
        int written = snprintf(hexbuf + hexpos, remaining, "%02x", buf[valOff + i]);
        if (written < 0) {
            break;
        }
        hexpos += (size_t)written;
        if (hexpos + HEX_SAFETY_MARGIN >= sizeof(hexbuf)) {
            break;
        }
    }
    printf(": %s", hexbuf);
    if (dotted) {
        const char *name = OidLookupName(dotted);
        if (name) {
            printf(" (%s : %s)", dotted, name);
        } else {
            printf(" (%s)", dotted);
        }
        BSL_SAL_FREE(dotted);
    }
    printf("\n");
}

static void PrintIntegerValue(const uint8_t *buf, size_t bufLen, size_t valOff, size_t contentLen)
{
    if (contentLen == 0) {
        printf("\n");
        return;
    }

    if (valOff >= bufLen || contentLen > bufLen - valOff) {
        printf("\n");
        return;
    }

    size_t show = (contentLen < MAX_VALUE_DISPLAY_BYTES) ? contentLen : MAX_VALUE_DISPLAY_BYTES;
    printf(": ");
    for (size_t i = 0; i < show; i++) {
        printf("%02x", buf[valOff + i]);
    }
    if (show < contentLen) {
        printf("...");
    }
    printf("\n");
}

static void PrintOctetStringValue(const uint8_t *buf, size_t bufLen, size_t valOff, size_t contentLen)
{
    if (valOff >= bufLen || contentLen > bufLen - valOff) {
        printf("\n");
        return;
    }

    size_t checkLen = (contentLen < MAX_VALUE_DISPLAY_BYTES) ? contentLen : MAX_VALUE_DISPLAY_BYTES;
    bool printable = true;
    for (size_t i = 0; i < checkLen; i++) {
        uint8_t c = buf[valOff + i];
        if (c < ASCII_PRINTABLE_MIN || c > ASCII_PRINTABLE_MAX) {
            printable = false;
            break;
        }
    }
    size_t show = (contentLen < MAX_VALUE_DISPLAY_BYTES) ? contentLen : MAX_VALUE_DISPLAY_BYTES;
    if (printable) {
        printf(": \"");
        for (size_t i = 0; i < show; i++) {
            putchar((char)buf[valOff + i]);
        }
        if (show < contentLen) {
            printf("...");
        }
        printf("\"");
    } else {
        printf(": [HEX DUMP]:");
        for (size_t i = 0; i < show; i++) {
            printf("%02x", buf[valOff + i]);
        }
        if (show < contentLen) {
            printf("...");
        }
    }
    printf("\n");
}

/* ASN.1 parse context */
typedef struct {
    bool showIndent;
    bool showValue;
} ParseContext;

/* ASN.1 node information for printing */
typedef struct {
    size_t offset;
    int depth;
    size_t headerLen;
    size_t contentLen;
    unsigned int tagClass;
    bool constructed;
    unsigned long long tagNumber;
} NodeInfo;

typedef struct {
    const uint8_t *buf;
    size_t bufLen;
    size_t baseOff;
    size_t availLen;
    int depth;
    const ParseContext *ctx;
} ParseRecursiveParams;

static int ParseRecursive(const ParseRecursiveParams *params);

static void PrintDefaultValue(const uint8_t *buf, size_t bufLen, size_t valOff, size_t contentLen)
{
    if (valOff >= bufLen || contentLen > bufLen - valOff) {
        printf("\n");
        return;
    }

    size_t show = (contentLen < MAX_VALUE_DISPLAY_BYTES) ? contentLen : MAX_VALUE_DISPLAY_BYTES;
    bool printable = true;
    for (size_t i = 0; i < show; i++) {
        uint8_t c = buf[valOff + i];
        if (c < ASCII_PRINTABLE_MIN || c > ASCII_PRINTABLE_MAX) {
            printable = false;
            break;
        }
    }
    if (printable) {
        printf(": \"");
        for (size_t i = 0; i < show; i++) {
            putchar((char)buf[valOff + i]);
        }
        if (show < contentLen) {
            printf("...");
        }
        printf("\"\n");
    } else {
        printf(": ");
        for (size_t i = 0; i < show; i++) {
            printf("%02x", buf[valOff + i]);
        }
        if (show < contentLen) {
            printf("...");
        }
        printf("\n");
    }
}

static void PrintNodeLine(const NodeInfo *node, const uint8_t *buf, size_t bufLen, const ParseContext *ctx)
{
    char typebuf[TYPEBUF_SIZE] = {0};
    if (node->tagClass == ASN1_CLASS_CONTEXT) {
        if (node->constructed) {
            (void)snprintf(typebuf, sizeof(typebuf), "cont [ %llu ]", node->tagNumber);
        } else {
            (void)snprintf(typebuf, sizeof(typebuf), "[%llu] CONTEXT", node->tagNumber);
        }
    } else if (node->tagClass == ASN1_CLASS_APPLICATION) {
        (void)snprintf(typebuf, sizeof(typebuf), "[%llu] APPLICATION", node->tagNumber);
    } else if (node->tagClass == ASN1_CLASS_PRIVATE) {
        (void)snprintf(typebuf, sizeof(typebuf), "[%llu] PRIVATE", node->tagNumber);
    } else {
        TagToNameStr(node->tagClass, node->tagNumber, typebuf, sizeof(typebuf));
    }

    (void)fprintf(stdout, "%4zu:d=%d  hl=%2zu l=%5zu %s ",
        node->offset, node->depth,
        node->headerLen, node->contentLen,
        node->constructed ? "cons:" : "prim:");
    if (ctx->showIndent) {
        for (int i = 0; i < node->depth; i++) {
            (void)fprintf(stdout, "  ");
        }
    }
    (void)fprintf(stdout, "%-20s", typebuf);

    if (!ctx->showValue || node->constructed) {
        fprintf(stdout, "\n");
        fflush(stdout);
        return;
    }

    size_t valOff = node->offset + node->headerLen;
    if (valOff >= bufLen || node->contentLen > bufLen - valOff) {
        printf("\n");
        return;
    }

    if (node->tagClass == ASN1_CLASS_UNIVERSAL && node->tagNumber == ASN1_TAG_OBJECT_IDENTIFIER) {
        PrintOidValue(buf, bufLen, valOff, node->contentLen);
        return;
    }

    if (node->tagClass == ASN1_CLASS_UNIVERSAL && node->tagNumber == ASN1_TAG_INTEGER) {
        PrintIntegerValue(buf, bufLen, valOff, node->contentLen);
        return;
    }
    
    if (node->tagClass == ASN1_CLASS_UNIVERSAL && node->tagNumber == ASN1_TAG_OCTET_STRING) {
        PrintOctetStringValue(buf, bufLen, valOff, node->contentLen);
        return;
    }

    PrintDefaultValue(buf, bufLen, valOff, node->contentLen);
}

/* embedded DER context */
typedef struct {
    size_t contentOff;
    size_t contentLen;
    size_t end;
    int depth;
} EmbeddedContext;

static int ParseEmbeddedDer(const uint8_t *buf, size_t bufLen, const EmbeddedContext *embedded,
    const ParseContext *ctx)
{
    size_t innerOff = embedded->contentOff + 1;
    size_t innerLen = (embedded->contentLen > 1) ? (embedded->contentLen - 1) : 0;
    if (innerOff + MIN_BER_HEADER_SIZE > embedded->end || innerLen < MIN_BER_HEADER_SIZE) {
        return HITLS_APP_SUCCESS;
    }

    Asn1TagInfo itagInfo = {0};
    if (ReadTag(buf, bufLen, innerOff, &itagInfo) != HITLS_APP_SUCCESS) {
        return HITLS_APP_SUCCESS;
    }

    size_t ilenLen = 0;
    size_t icontentLen = 0;
    if (ReadLength(buf, bufLen, innerOff + itagInfo.tagBytes, &ilenLen, &icontentLen) != HITLS_APP_SUCCESS) {
        return HITLS_APP_SUCCESS;
    }

    bool sizeMatches = (itagInfo.tagBytes + ilenLen + icontentLen) <= innerLen;
    bool isUniversalClass = itagInfo.tagClass == ASN1_CLASS_UNIVERSAL;
    bool isCommonContainer = (itagInfo.tagNumber == ASN1_TAG_SEQUENCE ||
                              itagInfo.tagNumber == ASN1_TAG_SET ||
                              itagInfo.tagNumber == ASN1_TAG_OCTET_STRING);
    bool hasValidLengths = (itagInfo.tagBytes <= MAX_TAG_BYTES && ilenLen <= MAX_LEN_BYTES);

    bool isPlausibleDer = sizeMatches && isUniversalClass && isCommonContainer && hasValidLengths;
    if (isPlausibleDer) {
        ParseRecursiveParams params = {
            .buf = buf,
            .bufLen = bufLen,
            .baseOff = innerOff,
            .availLen = innerLen,
            .depth = embedded->depth + 1,
            .ctx = ctx
        };
        return ParseRecursive(&params);
    }
    return HITLS_APP_SUCCESS;
}

typedef struct {
    size_t p;
    size_t headerLen;
    size_t contentLen;
    Asn1TagInfo tagInfo;
} ParseNodeResult;

static int ParseSingleNode(const uint8_t *buf, size_t bufLen, size_t p, ParseNodeResult *result)
{
    if (ReadTag(buf, bufLen, p, &result->tagInfo) != HITLS_APP_SUCCESS) {
        AppPrintError("ReadTag failed at %lu\n", (unsigned long)p);
        return HITLS_APP_DECODE_FAIL;
    }

    size_t lenLen = 0;
    if (ReadLength(buf, bufLen, p + result->tagInfo.tagBytes, &lenLen, &result->contentLen) != HITLS_APP_SUCCESS) {
        AppPrintError("Unsupported length form at %lu\n", (unsigned long)p);
        return HITLS_APP_DECODE_FAIL;
    }

    result->headerLen = result->tagInfo.tagBytes + lenLen;
    if (result->headerLen > SIZE_MAX - result->contentLen) {
        AppPrintError("Length overflow at %lu\n", (unsigned long)p);
        return HITLS_APP_DECODE_FAIL;
    }

    result->p = p;
    return HITLS_APP_SUCCESS;
}

static int ValidateNodeBounds(size_t p, size_t headerLen, size_t contentLen, size_t bufLen, size_t end)
{
    if (p + headerLen + contentLen > bufLen) {
        AppPrintError("Out of bounds at %lu (need %lu bytes, buffer has %lu)\n",
            (unsigned long)p, (unsigned long)(headerLen + contentLen), (unsigned long)bufLen);
        return HITLS_APP_DECODE_FAIL;
    }
    
    if (p + headerLen + contentLen > end) {
        AppPrintError("Exceeds available length at %lu\n", (unsigned long)p);
        return HITLS_APP_DECODE_FAIL;
    }

    return HITLS_APP_SUCCESS;
}

typedef struct {
    const uint8_t *buf;
    size_t bufLen;
    const ParseNodeResult *result;
    int depth;
    size_t end;
    const ParseContext *ctx;
} ProcessNodeParams;

static int ProcessParsedNode(const ProcessNodeParams *params)
{
    NodeInfo nodeInfo = {
        .offset = params->result->p,
        .depth = params->depth,
        .headerLen = params->result->headerLen,
        .contentLen = params->result->contentLen,
        .tagClass = params->result->tagInfo.tagClass,
        .constructed = params->result->tagInfo.constructed,
        .tagNumber = params->result->tagInfo.tagNumber
    };
    PrintNodeLine(&nodeInfo, params->buf, params->bufLen, params->ctx);

    size_t contentOff = params->result->p + params->result->headerLen;
    if (params->result->tagInfo.constructed) {
        ParseRecursiveParams recursiveParams = {
            .buf = params->buf,
            .bufLen = params->bufLen,
            .baseOff = contentOff,
            .availLen = params->result->contentLen,
            .depth = params->depth + 1,
            .ctx = params->ctx
        };
        return ParseRecursive(&recursiveParams);
    } else if (params->result->tagInfo.tagClass == ASN1_CLASS_UNIVERSAL &&
               params->result->tagInfo.tagNumber == ASN1_TAG_BIT_STRING &&
               params->result->contentLen > 1) {
        EmbeddedContext embedded = {
            .contentOff = contentOff,
            .contentLen = params->result->contentLen,
            .end = params->end,
            .depth = params->depth
        };
        return ParseEmbeddedDer(params->buf, params->bufLen, &embedded, params->ctx);
    }
    return HITLS_APP_SUCCESS;
}

static int ParseRecursive(const ParseRecursiveParams *params)
{
    if (params->depth > MAX_PARSE_DEPTH) {
        AppPrintError("ASN.1 nesting too deep\n");
        return HITLS_APP_INVALID_ARG;
    }

    size_t p = params->baseOff;
    size_t end = params->baseOff + params->availLen;

    if (params->baseOff >= params->bufLen || params->availLen == 0 || end > params->bufLen) {
        return HITLS_APP_SUCCESS;
    }

    while (p < end) {
        ParseNodeResult result = {0};
        if (ParseSingleNode(params->buf, params->bufLen, p, &result) != HITLS_APP_SUCCESS) {
            return HITLS_APP_DECODE_FAIL;
        }

        if (ValidateNodeBounds(p, result.headerLen, result.contentLen, params->bufLen, end) != HITLS_APP_SUCCESS) {
            return HITLS_APP_DECODE_FAIL;
        }

        ProcessNodeParams processParams = {
            .buf = params->buf,
            .bufLen = params->bufLen,
            .result = &result,
            .depth = params->depth,
            .end = end,
            .ctx = params->ctx
        };
        int rc = ProcessParsedNode(&processParams);
        if (rc != HITLS_APP_SUCCESS) {
            return rc;
        }
        p += result.headerLen + result.contentLen;
    }
    return HITLS_APP_SUCCESS;
}

int AppAsn1ComputeHeaderLenOfTlv(const uint8_t *tlv, size_t tlvLen, size_t *hdrLen)
{
    if (!tlv || !hdrLen || tlvLen == 0) {
        return HITLS_APP_INVALID_ARG;
    }
    Asn1TagInfo tagInfo = {0};
    if (ReadTag(tlv, tlvLen, 0, &tagInfo) != HITLS_APP_SUCCESS) {
        return HITLS_APP_DECODE_FAIL;
    }
    size_t lenLen = 0;
    size_t contentLen = 0;
    if (ReadLength(tlv, tlvLen, tagInfo.tagBytes, &lenLen, &contentLen) != HITLS_APP_SUCCESS) {
        return HITLS_APP_DECODE_FAIL;
    }
    *hdrLen = tagInfo.tagBytes + lenLen;
    return HITLS_APP_SUCCESS;
}

int AppAsn1GetNodeBytes(const uint8_t *buf, size_t bufLen, size_t offset, uint8_t **outBuf, size_t *outLen)
{
    if (!buf || !outBuf || !outLen) {
        return HITLS_APP_INVALID_ARG;
    }
    Asn1TagInfo tagInfo = {0};
    if (ReadTag(buf, bufLen, offset, &tagInfo) != HITLS_APP_SUCCESS) {
        return HITLS_APP_DECODE_FAIL;
    }
    size_t lenLen = 0;
    size_t contentLen = 0;
    if (ReadLength(buf, bufLen, offset + tagInfo.tagBytes, &lenLen, &contentLen) != HITLS_APP_SUCCESS) {
        return HITLS_APP_DECODE_FAIL;
    }
    size_t total = tagInfo.tagBytes + lenLen + contentLen;
    if (offset + total > bufLen) {
        return HITLS_APP_DECODE_FAIL;
    }
    uint8_t *out = (uint8_t *)BSL_SAL_Calloc(total, 1);
    if (!out) {
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    memcpy(out, buf + offset, total);
    *outBuf = out;
    *outLen = total;
    return HITLS_APP_SUCCESS;
}

int AppAsn1ParseBuffer(const uint8_t *buf, size_t bufLen, int showIndent, int showValue)
{
    if (!buf || bufLen == 0) {
        return HITLS_APP_INVALID_ARG;
    }
    ParseContext ctx = { showIndent ? true : false, showValue ? true : false };
    ParseRecursiveParams params = {
        .buf = buf,
        .bufLen = bufLen,
        .baseOff = 0,
        .availLen = bufLen,
        .depth = 0,
        .ctx = &ctx
    };
    return ParseRecursive(&params);
}

static void HexDumpNode(const uint8_t *node, size_t nodeLen)
{
    size_t bytesPerLine = HEX_DUMP_BYTES_PER_LINE;
    for (size_t i = 0; i < nodeLen; i += bytesPerLine) {
        printf("%4zu: ", i);
        for (size_t j = 0; j < bytesPerLine; j++) {
            if (i + j < nodeLen) {
                printf("%02x ", node[i + j]);
            } else {
                printf("   ");
            }
        }
        printf("  ");
        for (size_t j = 0; j < bytesPerLine && i + j < nodeLen; j++) {
            unsigned char c = node[i + j];
            putchar((c >= ASCII_PRINTABLE_MIN && c <= ASCII_PRINTABLE_MAX) ? c : '.');
        }
        printf("\n");
    }
}

static int WriteNodeValue(const uint8_t *node, size_t nodeLen, const char *outpath)
{
    size_t hdr = 0;
    if (AppAsn1ComputeHeaderLenOfTlv(node, nodeLen, &hdr) != HITLS_APP_SUCCESS) {
        AppPrintError("Invalid TLV header\n");
        return HITLS_APP_INTERNAL_EXCEPTION;
    }
    if (hdr > nodeLen) {
        AppPrintError("Header length larger than node\n");
        return HITLS_APP_INTERNAL_EXCEPTION;
    }

    const uint8_t *valuePtr = node + hdr;
    size_t valueLen = nodeLen - hdr;
    BSL_UIO *uio = HITLS_APP_UioOpen(outpath, 'w', outpath != NULL ? 1 : 0);
    if (uio == NULL) {
        AppPrintError("Failed to open output file %s\n", outpath);
        return HITLS_APP_UIO_FAIL;
    }

    uint8_t *tmpBuf = (uint8_t *)BSL_SAL_Calloc(valueLen, 1);
    if (!tmpBuf) {
        BSL_UIO_Free(uio);
        AppPrintError("Memory allocation failed\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    memcpy(tmpBuf, valuePtr, valueLen);

    int wret = HITLS_APP_OptWriteUio(uio, tmpBuf, (uint32_t)valueLen, HITLS_APP_FORMAT_BINARY);
    BSL_SAL_FREE(tmpBuf);
    BSL_UIO_Free(uio);
    if (wret != HITLS_APP_SUCCESS) {
        AppPrintError("Failed to write out value to %s\n", outpath);
        return wret;
    }
    printf("Wrote %zu bytes (value only) to %s\n", valueLen, outpath);
    return HITLS_APP_SUCCESS;
}

/* command line options */
typedef struct {
    char *infile;
    char *outpath;
    bool showIndent;
    bool doDump;
    bool noout;
    bool hasStrparse;
    BSL_ParseFormat inform;
    uint32_t strparseOff;
} Asn1ParseOptions;

static int ProcessStrparseNode(uint8_t *derbuf, size_t derlen, const Asn1ParseOptions *opts)
{
    uint8_t *node = NULL;
    size_t nodeLen = 0;
    int ret = AppAsn1GetNodeBytes(derbuf, derlen, (size_t)opts->strparseOff, &node, &nodeLen);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("Failed to extract node at offset %u\n", opts->strparseOff);
        return HITLS_APP_OPT_VALUE_INVALID;
    }

    if (!opts->noout) {
        AppAsn1ParseBuffer(node, nodeLen, opts->showIndent ? 1 : 0, opts->noout ? 0 : 1);
    }

    if (opts->doDump) {
        HexDumpNode(node, nodeLen);
    }

    int result = HITLS_APP_SUCCESS;
    if (opts->outpath) {
        result = WriteNodeValue(node, nodeLen, opts->outpath);
    }

    BSL_SAL_FREE(node);
    return result;
}

static int HandleAsn1Option(int32_t opt, Asn1ParseOptions *opts)
{
    switch (opt) {
        case OPT_ASN1PARSE_IN:
            opts->infile = HITLS_APP_OptGetValueStr();
            break;
        case OPT_ASN1PARSE_INDENT:
            opts->showIndent = true;
            break;
        case OPT_ASN1PARSE_DUMP:
            opts->doDump = true;
            break;
        case OPT_ASN1PARSE_NOOUT:
            opts->noout = true;
            break;
        case OPT_ASN1PARSE_OUT:
            opts->outpath = HITLS_APP_OptGetValueStr();
            break;
        case OPT_ASN1PARSE_INFORM: {
            BSL_ParseFormat fmt = 0;
            if (HITLS_APP_OptGetFormatType(HITLS_APP_OptGetValueStr(),
                HITLS_APP_OPT_VALUETYPE_FMT_PEMDER, &fmt) != HITLS_APP_SUCCESS) {
                AppPrintError("Invalid inform value\n");
                return HITLS_APP_OPT_UNKOWN;
            }
            opts->inform = fmt;
            break;
        }
        case OPT_ASN1PARSE_STRPARSE: {
            char *valueStr = HITLS_APP_OptGetValueStr();
            uint32_t offset = 0;
            if (HITLS_APP_OptGetUint32(valueStr, &offset) != HITLS_APP_SUCCESS) {
                AppPrintError("Invalid -strparse offset value\n");
                return HITLS_APP_OPT_UNKOWN;
            }
            opts->strparseOff = offset;
            opts->hasStrparse = true;
            break;
        }
        case OPT_ASN1PARSE_HELP:
            HITLS_APP_OptHelpPrint(asn1_cmd_options);
            return 1;
        default:
            return HITLS_APP_OPT_UNKOWN;
    }
    return 0;
}

static int ParseAsn1Options(int argc, char **argv, Asn1ParseOptions *opts)
{
    if (HITLS_APP_OptBegin(argc, argv, asn1_cmd_options) != HITLS_APP_SUCCESS) {
        AppPrintError("Option init failed\n");
        return HITLS_APP_INTERNAL_EXCEPTION;
    }

    int32_t opt;
    while ((opt = HITLS_APP_OptNext()) != HITLS_APP_OPT_EOF) {
        int result = HandleAsn1Option(opt, opts);
        if (result != 0) {
            HITLS_APP_OptEnd();
            return result;
        }
    }

    HITLS_APP_OptEnd();
    return 0;
}

static int PrepareNullTermBuffer(uint8_t *filebuf, size_t filelen, uint8_t **nullTermBuf)
{
    *nullTermBuf = (uint8_t *)BSL_SAL_Calloc(filelen + 1, 1);
    if (*nullTermBuf == NULL) {
        BSL_SAL_FREE(filebuf);
        AppPrintError("Memory allocation failed\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }

    memcpy(*nullTermBuf, filebuf, filelen);
    (*nullTermBuf)[filelen] = '\0';
    BSL_SAL_FREE(filebuf);
    return HITLS_APP_SUCCESS;
}

static int DecodePemData(char *charBuf, size_t filelen, uint8_t **asn1Data, uint32_t *asn1Len)
{
    BSL_PEM_Symbol symbol = {0};
    const char *dataType = NULL;

    int32_t symbolRet = BSL_PEM_GetSymbolAndType(charBuf, (uint32_t)filelen, &symbol, &dataType);
    if (symbolRet != BSL_SUCCESS) {
        AppPrintError("Failed to get PEM symbol (error code: %d)\n", symbolRet);
        return HITLS_APP_DECODE_FAIL;
    }

    char *pemPtr = charBuf;
    uint32_t pemLenVal = (uint32_t)filelen;

    int32_t decodeRet = BSL_PEM_DecodePemToAsn1(&pemPtr, &pemLenVal, &symbol, asn1Data, asn1Len);
    if (decodeRet != BSL_SUCCESS) {
        if (*asn1Data != NULL) {
            BSL_SAL_FREE(*asn1Data);
        }
        AppPrintError("PEM decode failed (error code: %d)\n", decodeRet);
        return HITLS_APP_DECODE_FAIL;
    }

    if (*asn1Data == NULL || *asn1Len == 0) {
        if (*asn1Data != NULL) {
            BSL_SAL_FREE(*asn1Data);
        }
        AppPrintError("PEM decode returned empty data\n");
        return HITLS_APP_DECODE_FAIL;
    }

    return HITLS_APP_SUCCESS;
}

static int LoadAndConvertFile(const char *infile, BSL_ParseFormat inform,
    uint8_t **derbuf, size_t *derlen)
{
    uint8_t *filebuf = NULL;
    size_t filelen = 0;
    int ret = ReadFileToBuf(infile, &filebuf, &filelen, MAX_PEM_READ);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("Failed to read input file\n");
        return ret;
    }

    if (filelen == 0) {
        BSL_SAL_FREE(filebuf);
        AppPrintError("Empty input file\n");
        return HITLS_APP_INVALID_ARG;
    }

    if (inform == BSL_FORMAT_ASN1) {
        *derbuf = filebuf;
        *derlen = filelen;
        return HITLS_APP_SUCCESS;
    }

    uint8_t *nullTermBuf = NULL;
    ret = PrepareNullTermBuffer(filebuf, filelen, &nullTermBuf);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    char *charBuf = (char *)nullTermBuf;
    bool isPem = BSL_PEM_IsPemFormat(charBuf, (uint32_t)filelen);
    if (inform == BSL_FORMAT_PEM && !isPem) {
        BSL_SAL_FREE(nullTermBuf);
        AppPrintError("Input is not PEM format\n");
        return HITLS_APP_DECODE_FAIL;
    }
    if (inform == BSL_FORMAT_UNKNOWN && !isPem) {
        *derbuf = nullTermBuf;
        *derlen = filelen;
        return HITLS_APP_SUCCESS;
    }

    uint8_t *asn1Data = NULL;
    uint32_t asn1Len = 0;
    ret = DecodePemData(charBuf, filelen, &asn1Data, &asn1Len);
    BSL_SAL_FREE(nullTermBuf);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    *derbuf = asn1Data;
    *derlen = (size_t)asn1Len;
    return HITLS_APP_SUCCESS;
}

int HITLS_Asn1Main(int argc, char **argv)
{
    Asn1ParseOptions opts = {
        .infile = NULL,
        .outpath = NULL,
        .showIndent = false,
        .doDump = false,
        .noout = false,
        .hasStrparse = false,
        .inform = BSL_FORMAT_UNKNOWN,
        .strparseOff = 0
    };

    int parseResult = ParseAsn1Options(argc, argv, &opts);
    if (parseResult == 1) {
        return HITLS_APP_SUCCESS;
    }
    if (parseResult != 0) {
        return parseResult;
    }

    uint8_t *derbuf = NULL;
    size_t derlen = 0;
    int loadResult = LoadAndConvertFile(opts.infile, opts.inform, &derbuf, &derlen);
    if (loadResult != HITLS_APP_SUCCESS) {
        return loadResult;
    }

    if (derbuf == NULL || derlen == 0) {
        AppPrintError("Empty or invalid input data\n");
        BSL_SAL_FREE(derbuf);
        return HITLS_APP_INVALID_ARG;
    }

    int result;
    if (opts.hasStrparse) {
        result = ProcessStrparseNode(derbuf, derlen, &opts);
    } else {
        result = AppAsn1ParseBuffer(derbuf, derlen, opts.showIndent ? 1 : 0, opts.noout ? 0 : 1);
    }

    BSL_SAL_FREE(derbuf);
    return result;
}