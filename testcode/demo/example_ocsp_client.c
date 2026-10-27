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

/*
 * OCSP client demo.
 *
 * Usage:
 *     example_ocsp_client                 # use the preset PEM chain embedded below
 *     example_ocsp_client <cert.pem> <issuer.pem> [trusted_ca.pem]
 *
 * Reads the target certificate (PEM) and its issuer (PEM), takes the OCSP
 * responder URL from the certificate AIA extension, then opens a real TCP
 * connection to the responder, POSTs the OCSP request over HTTP and prints
 * the request / response with the print interface. The response is verified
 * (response status, nonce, validity, optional signature verification against
 * a trusted CA) and the certificate status is extracted.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "bsl_sal.h"
#include "bsl_err.h"
#include "bsl_uio.h"
#include "bsl_list.h"
#include "crypt_eal_init.h"
#include "crypt_algid.h"
#include "crypt_eal_md.h"
#include "hitls_cert_init.h"
#include "hitls_crypt_init.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_x509.h"
#include "hitls_pki_types.h"
#include "hitls_pki_utils.h"
#include "hitls_pki_ocsp.h"
#include "hitls_pki_ocsp_http.h"
#include "hitls_pki_errno.h"
#include "crypt_errno.h"

#define OCSP_CLIENT_POLL_TRIES  150
#define OCSP_CLIENT_POLL_MS     100
#define OCSP_CLIENT_CONNECT_SEC 5
#define OCSP_CLIENT_TIMEOUT_SEC 15
/* Clock-skew tolerance for the thisUpdate/nextUpdate checks. */
#define OCSP_CLIENT_VALIDITY_DRIFT_SEC 300
/* Maximum accepted age of thisUpdate. Real responders refresh thisUpdate every
 * ~6-24 h, so a strict limit rejects valid responses; 0 disables the check. */
#define OCSP_CLIENT_VALIDITY_MAXAGE_SEC 0

/* Preset certificate chain (PEM, from the demo dir *.crt files):
 * leaf "*.openhitls.net" (AIA OCSP URL http://status.geotrust.com)
 *   <- GeoTrust TLS RSA CA G1 (intermediate)
 *   <- DigiCert Global Root G2 (root).
 * Used when the demo is run without arguments. */
static const char g_presetRootPem[] = "-----BEGIN CERTIFICATE-----\n"
                                      "MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh\n"
                                      "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
                                      "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH\n"
                                      "MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT\n"
                                      "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j\n"
                                      "b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG\n"
                                      "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI\n"
                                      "2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx\n"
                                      "1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ\n"
                                      "q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz\n"
                                      "tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ\n"
                                      "vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP\n"
                                      "BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV\n"
                                      "5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY\n"
                                      "1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4\n"
                                      "NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG\n"
                                      "Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91\n"
                                      "8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe\n"
                                      "pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl\n"
                                      "MrY=\n"
                                      "-----END CERTIFICATE-----\n";

static const char g_presetCaPem[] = "-----BEGIN CERTIFICATE-----\n"
                                    "MIIEjTCCA3WgAwIBAgIQDQd4KhM/xvmlcpbhMf/ReTANBgkqhkiG9w0BAQsFADBh\n"
                                    "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
                                    "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH\n"
                                    "MjAeFw0xNzExMDIxMjIzMzdaFw0yNzExMDIxMjIzMzdaMGAxCzAJBgNVBAYTAlVT\n"
                                    "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j\n"
                                    "b20xHzAdBgNVBAMTFkdlb1RydXN0IFRMUyBSU0EgQ0EgRzEwggEiMA0GCSqGSIb3\n"
                                    "DQEBAQUAA4IBDwAwggEKAoIBAQC+F+jsvikKy/65LWEx/TMkCDIuWegh1Ngwvm4Q\n"
                                    "yISgP7oU5d79eoySG3vOhC3w/3jEMuipoH1fBtp7m0tTpsYbAhch4XA7rfuD6whU\n"
                                    "gajeErLVxoiWMPkC/DnUvbgi74BJmdBiuGHQSd7LwsuXpTEGG9fYXcbTVN5SATYq\n"
                                    "DfbexbYxTMwVJWoVb6lrBEgM3gBBqiiAiy800xu1Nq07JdCIQkBsNpFtZbIZhsDS\n"
                                    "fzlGWP4wEmBQ3O67c+ZXkFr2DcrXBEtHam80Gp2SNhou2U5U7UesDL/xgLK6/0d7\n"
                                    "6TnEVMSUVJkZ8VeZr+IUIlvoLrtjLbqugb0T3OYXW+CQU0kBAgMBAAGjggFAMIIB\n"
                                    "PDAdBgNVHQ4EFgQUlE/UXYvkpOKmgP792PkA76O+AlcwHwYDVR0jBBgwFoAUTiJU\n"
                                    "IBiV5uNu5g/6+rkS7QYXjzkwDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsG\n"
                                    "AQUFBwMBBggrBgEFBQcDAjASBgNVHRMBAf8ECDAGAQH/AgEAMDQGCCsGAQUFBwEB\n"
                                    "BCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEIGA1Ud\n"
                                    "HwQ7MDkwN6A1oDOGMWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEds\n"
                                    "b2JhbFJvb3RHMi5jcmwwPQYDVR0gBDYwNDAyBgRVHSAAMCowKAYIKwYBBQUHAgEW\n"
                                    "HGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDQYJKoZIhvcNAQELBQADggEB\n"
                                    "AIIcBDqC6cWpyGUSXAjjAcYwsK4iiGF7KweG97i1RJz1kwZhRoo6orU1JtBYnjzB\n"
                                    "c4+/sXmnHJk3mlPyL1xuIAt9sMeC7+vreRIF5wFBC0MCN5sbHwhNN1JzKbifNeP5\n"
                                    "ozpZdQFmkCo+neBiKR6HqIA+LMTMCMMuv2khGGuPHmtDze4GmEGZtYLyF8EQpa5Y\n"
                                    "jPuV6k2Cr/N3XxFpT3hRpt/3usU/Zb9wfKPtWpoznZ4/44c1p9rzFcZYrWkj3A+7\n"
                                    "TNBJE0GmP2fhXhP1D/XVfIW/h0yCJGEiV9Glm/uGOa3DXHlmbAcxSyCRraG+ZBkA\n"
                                    "7h4SeM6Y8l/7MBRpPCz6l8Y=\n"
                                    "-----END CERTIFICATE-----\n";

static const char g_presetLeafPem[] = "-----BEGIN CERTIFICATE-----\n"
                                      "MIIGrTCCBZWgAwIBAgIQCj1v22LCgaPx5gsYaSDlKDANBgkqhkiG9w0BAQsFADBg\n"
                                      "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
                                      "d3cuZGlnaWNlcnQuY29tMR8wHQYDVQQDExZHZW9UcnVzdCBUTFMgUlNBIENBIEcx\n"
                                      "MB4XDTI2MDcyNDAwMDAwMFoXDTI3MDIwNzIzNTk1OVowGjEYMBYGA1UEAwwPKi5v\n"
                                      "cGVuaGl0bHMubmV0MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAkZLx\n"
                                      "9N8gECXONV1glh3t1bcpnEpN2c1JpyzTAnEXQyKAY5Q9Kfnk9+HEzl8W++JAJ4/L\n"
                                      "5SbiiIy0dnDstJHZHAIuF07C6P4cpywTAwPPfgXgUehqrnIoLkHX9Ro8l9gUkadU\n"
                                      "pibYu439UQ2sbABNg/DuSo83smrtr7LPb0uho8oZd8xs3QSlgJNdxICF/JSLHCCv\n"
                                      "XM7ruTLwwiO519yklIRES93o9cWFHC3n+GPeRsnTgTnnGDNUN+18FeqFFvd6JDgT\n"
                                      "j8cCgfyak2Kb0Ioqv7lxTlielKH3fPkeSDaqMOxACV1JjW6FP/qyET6GigsCi/7s\n"
                                      "WnPk9Ku1LZPKJB8Ujh+GgW+gjDPuDd0hQdyCaVkLj7YPBATcmPPOXF1oy30sWSsI\n"
                                      "LRkyZB6wcetfZNLMhre+b8aYJRbvKpH9DKgNxc+YBltEfr+hv67WoPRly4jMcTPi\n"
                                      "vtCJB27NSfa/fKt3yxZZmZwEhk8AUrB5sX2ot6GCGqfVCGCDh+QJcqs/soxbAgMB\n"
                                      "AAGjggMnMIIDIzAfBgNVHSMEGDAWgBSUT9Rdi+Sk4qaA/v3Y+QDvo74CVzAdBgNV\n"
                                      "HQ4EFgQUzD6JkNt1v1MohD1W9Gy0Mp5EsW4wKQYDVR0RBCIwIIIPKi5vcGVuaGl0\n"
                                      "bHMubmV0gg1vcGVuaGl0bHMubmV0MD4GA1UdIAQ3MDUwMwYGZ4EMAQIBMCkwJwYI\n"
                                      "KwYBBQUHAgEWG2h0dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAOBgNVHQ8BAf8E\n"
                                      "BAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMD8GA1UdHwQ4MDYw\n"
                                      "NKAyoDCGLmh0dHA6Ly9jZHAuZ2VvdHJ1c3QuY29tL0dlb1RydXN0VExTUlNBQ0FH\n"
                                      "MS5jcmwwdgYIKwYBBQUHAQEEajBoMCYGCCsGAQUFBzABhhpodHRwOi8vc3RhdHVz\n"
                                      "Lmdlb3RydXN0LmNvbTA+BggrBgEFBQcwAoYyaHR0cDovL2NhY2VydHMuZ2VvdHJ1\n"
                                      "c3QuY29tL0dlb1RydXN0VExTUlNBQ0FHMS5jcnQwDAYDVR0TAQH/BAIwADCCAX4G\n"
                                      "CisGAQQB1nkCBAIEggFuBIIBagFoAHcATGPcmOWcHauI9h6KPd6uj6tEozd7X5uU\n"
                                      "w/uhnPzBviYAAAGfkeSEUwAABAMASDBGAiEAvDRx8mUC9mbijEpTTzIneDA3ylrH\n"
                                      "uaveXpjTNANlscECIQC2jwkUlPw4Hyv5raFaGKieTRU1ZeXmBdmtC/KuSayrUQB1\n"
                                      "ANbVjanQF1Pzakqgx1dJAq/rx9ws04zZ92TIDIkZHp8CAAABn5HkhG8AAAQDAEYw\n"
                                      "RAIgG11LWAcVjF4VyDS3vWH4Ss6siWu6/W5mDCGObmiY3JgCIHVdF7QuXUt9QD70\n"
                                      "Xelg0SgDwtJ8UL9saNzJstue8Xn9AHYARMK9DOkUDmSlyUoBkwpaobs1lw4A7hEW\n"
                                      "iWgqHETXtWYAAAGfkeSEjAAABAMARzBFAiBJFRGJ6qcU+QxGN0LubsuwGo/kEQ5T\n"
                                      "UGyqfAzSFIVO2AIhAJq1GgSLo2lM2xDNz8AHhKNykGkcvgOjPfp7vlHinVlEMA0G\n"
                                      "CSqGSIb3DQEBCwUAA4IBAQCGyPawPfG+YcPxGmzuFqIHLx0qjrcLHX5hrT3K0IRs\n"
                                      "w7+GxjZ9qcAXG4/4u9ps6WNvJN2ILkkvcptR+f8IS7BMLj8ere6QmZ9zkpuqlsL/\n"
                                      "shH9PPXYZZZ3XyU8VJwhhcHUmtMNLIQ0TzRXDGlFA8X7FZerE+hN5DFqIEyVvCDr\n"
                                      "/deBhahcZ8HE8WTsB0G7Ryox4fmPt1kx5+HYQYSI/uMA2Uw7Lw181smpC5d+9esb\n"
                                      "3D3EqFm/aGJBoxRJZqQaVtDZZup+IycoInEQ6vUo1qh7dwfAOinYd/V+5BzjYxJq\n"
                                      "ESCJ3XEUnz2Z+72pxexpETSoGoz1fRzHJmeNVzaqvR2I\n"
                                      "-----END CERTIFICATE-----\n";

/* Mirror of the internal BSL_BufMem returned by the memory UIO (same layout:
 * { size_t length; char *data; size_t max; }) so the print output can be read
 * without depending on an internal header. */
typedef struct {
    size_t length;
    char *data;
    size_t max;
} OcspClientBufMem;

static void OcspClientPrintBuf(BSL_UIO *uio)
{
    OcspClientBufMem *bm = NULL;
    if (BSL_UIO_Ctrl(uio, BSL_UIO_MEM_GET_PTR, (int32_t)sizeof(OcspClientBufMem *), &bm) != BSL_SUCCESS || bm == NULL ||
        bm->length == 0) {
        printf("    (empty output)\n");
        return;
    }
    /* Clamp to INT_MAX so the %.*s precision cannot wrap negative. */
    size_t len = bm->length;
    int printLen = (len > (size_t)INT_MAX) ? INT_MAX : (int)len;
    printf("%.*s", printLen, bm->data);
    if (bm->data[bm->length - 1] != '\n') {
        printf("\n");
    }
}

static int32_t OcspClientPrintReq(const HITLS_OCSP_Req *req)
{
    BSL_UIO *uio = BSL_UIO_New(BSL_UIO_MemMethod());
    if (uio == NULL) {
        return -1;
    }
    int32_t ret = HITLS_PKI_PrintCtrl(HITLS_PKI_PRINT_OCSP_REQ, (void *)(uintptr_t)req, sizeof(HITLS_OCSP_Req *), uio);
    OcspClientPrintBuf(uio);
    BSL_UIO_Free(uio);
    return ret;
}

static int32_t OcspClientPrintResp(const HITLS_OCSP_Resp *resp)
{
    BSL_UIO *uio = BSL_UIO_New(BSL_UIO_MemMethod());
    if (uio == NULL) {
        return -1;
    }
    int32_t ret =
        HITLS_PKI_PrintCtrl(HITLS_PKI_PRINT_OCSP_RESP, (void *)(uintptr_t)resp, sizeof(HITLS_OCSP_Resp *), uio);
    OcspClientPrintBuf(uio);
    BSL_UIO_Free(uio);
    return ret;
}

static void OcspClientFreeUrl(void *value)
{
    if (value == NULL) {
        return;
    }
    BSL_Buffer *b = (BSL_Buffer *)value;
    BSL_SAL_Free(b->data);
    BSL_SAL_Free(b);
}

static void OcspClientNoopFree(void *value)
{
    (void)value; /* certs stay owned by the caller */
}

/* Split an absolute http(s) URL into host, port and path. Only the http:// scheme
 * is accepted here (plain HTTP to the OCSP responder); port defaults to 80 and a
 * missing path defaults to "/". */
static int32_t OcspClientParseUrl(const char *url, char *host, uint32_t hostCap, uint16_t *port, char *path,
                                  uint32_t pathCap)
{
    if (url == NULL || host == NULL || port == NULL || path == NULL) {
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    const char *p;
    if (strncmp(url, "http://", 7) == 0) {
        *port = 80;
        p = url + 7;
    } else if (strncmp(url, "https://", 8) == 0) {
        /* This demo opens a plain TCP connection and has no TLS client, so an
         * https URL must not be silently downgraded to plaintext port 80. */
        printf("    https:// is not supported by this demo (no TLS client); use http://\n");
        return HITLS_OCSP_ERR_INVALID_PARAM;
    } else {
        printf("    unsupported URL scheme\n");
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }
    if (*p == '[') {
        /* RFC 3986 bracket-delimited IPv6 literals contain ':' inside the
         * brackets; the ':'-based host scan below would mis-split them. */
        printf("    IPv6 literal URLs are not supported by this demo\n");
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }
    const char *q = p;
    while (*q != '\0' && *q != ':' && *q != '/') {
        q++;
    }
    size_t hostLen = (size_t)(q - p);
    if (hostLen == 0 || hostLen >= hostCap) {
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }
    (void)memcpy(host, p, hostLen);
    host[hostLen] = '\0';
    if (*q == ':') {
        const char *portStart = q + 1;
        const char *r = portStart;
        while (*r != '\0' && *r != '/') {
            r++;
        }
        size_t portLen = (size_t)(r - portStart);
        if (portLen == 0 || portLen >= 8) {
            return HITLS_OCSP_ERR_INVALID_PARAM;
        }
        char portBuf[8];
        (void)memcpy(portBuf, portStart, portLen);
        portBuf[portLen] = '\0';
        int pv = atoi(portBuf);
        if (pv <= 0 || pv > 65535) {
            return HITLS_OCSP_ERR_INVALID_PARAM;
        }
        *port = (uint16_t)pv;
        q = r;
    }
    if (*q == '/') {
        size_t pathLen = strlen(q);
        if (pathLen >= pathCap) {
            return HITLS_OCSP_ERR_INVALID_PARAM;
        }
        (void)memcpy(path, q, pathLen);
        path[pathLen] = '\0';
    } else {
        (void)memcpy(path, "/", 2);
    }
    return HITLS_PKI_SUCCESS;
}

static const char *OcspClientNonceStr(int32_t status)
{
    if (status == HITLS_OCSP_NONCE_EQUAL) {
        return "equal";
    }
    if (status == HITLS_OCSP_NONCE_BOTH_ABSENT) {
        return "both absent";
    }
    if (status == HITLS_OCSP_NONCE_RESP_ONLY) {
        return "response only (abnormal)";
    }
    if (status == HITLS_OCSP_NONCE_REQ_ONLY) {
        return "request only (acceptable)";
    }
    return "not equal";
}

int main(int argc, char *argv[])
{
    int32_t rc = 1;
    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *issuer = NULL;
    HITLS_X509_Cert *ca = NULL;
    BslList *urls = NULL;
    struct addrinfo *res = NULL;
    int fd = -1;
    BSL_UIO *uio = NULL;
    CRYPT_EAL_MdCtx *mdCtx = NULL;
    HITLS_OCSP_CertId *certId = NULL;
    HITLS_OCSP_SingleReq *singleReq = NULL;
    HITLS_OCSP_Req *req = NULL;
    HITLS_HTTP_ReqCtx *ctx = NULL;
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_X509_StoreCtx *store = NULL;
    BslList *signerCerts = NULL;
    char url[256];
    char host[128] = {0};
    char path[256] = {0};
    char portStr[8];
    uint16_t port = 0;
    struct addrinfo hints;
    int32_t ret;
    const char *outputPath = NULL;

    if (CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL) != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed.\n");
        goto EXIT;
    }
    HITLS_CertMethodInit();
    HITLS_CryptMethodInit();

    /* Extract the optional --output <file> (DER OCSP response dump) and collect
     * up to three positional cert files (cert, issuer, optional trusted CA). */
    const char *posArgs[3] = {NULL, NULL, NULL};
    int32_t posCount = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--output") == 0) {
            if (i + 1 >= argc) {
                printf("--output requires a file path.\n");
                goto EXIT;
            }
            outputPath = argv[++i];
        } else if (posCount < 3) {
            posArgs[posCount++] = argv[i];
        } else {
            printf("too many arguments.\n");
            goto EXIT;
        }
    }

    /* Load the target cert and its issuer (PEM only). Without arguments the demo
     * uses the preset chain (*.openhitls.net <- GeoTrust TLS RSA CA G1 <- DigiCert
     * Global Root G2) embedded below. */
    if (posCount >= 2) {
        if (HITLS_X509_CertParseFile(BSL_FORMAT_PEM, posArgs[0], &cert) != HITLS_PKI_SUCCESS) {
            printf("failed to parse cert (PEM): %s\n", posArgs[0]);
            goto EXIT;
        }
        if (HITLS_X509_CertParseFile(BSL_FORMAT_PEM, posArgs[1], &issuer) != HITLS_PKI_SUCCESS) {
            printf("failed to parse issuer (PEM): %s\n", posArgs[1]);
            goto EXIT;
        }
        if (posCount > 2 && HITLS_X509_CertParseFile(BSL_FORMAT_PEM, posArgs[2], &ca) != HITLS_PKI_SUCCESS) {
            printf("failed to parse trusted CA (PEM): %s\n", posArgs[2]);
            goto EXIT;
        }
    } else {
        printf("using the preset certificate chain (PEM):\n");
        BSL_Buffer leafBuf = {(uint8_t *)g_presetLeafPem, sizeof(g_presetLeafPem)};
        if (HITLS_X509_CertParseBuff(BSL_FORMAT_PEM, &leafBuf, &cert) != HITLS_PKI_SUCCESS) {
            printf("failed to parse the preset leaf cert.\n");
            goto EXIT;
        }
        BSL_Buffer caBuf = {(uint8_t *)g_presetCaPem, sizeof(g_presetCaPem)};
        if (HITLS_X509_CertParseBuff(BSL_FORMAT_PEM, &caBuf, &issuer) != HITLS_PKI_SUCCESS) {
            printf("failed to parse the preset intermediate CA.\n");
            goto EXIT;
        }
        BSL_Buffer rootBuf = {(uint8_t *)g_presetRootPem, sizeof(g_presetRootPem)};
        if (HITLS_X509_CertParseBuff(BSL_FORMAT_PEM, &rootBuf, &ca) != HITLS_PKI_SUCCESS) {
            printf("failed to parse the preset root CA.\n");
            goto EXIT;
        }
        printf("    cert   : *.openhitls.net\n");
        printf("    issuer : GeoTrust TLS RSA CA G1\n");
        printf("    ca     : DigiCert Global Root G2\n");
    }

    /* Extract the OCSP responder URL from the certificate AIA. */
    if (HITLS_OCSP_GetCertOcspUrls(cert, &urls) != HITLS_PKI_SUCCESS) {
        printf("certificate carries no OCSP access-location URI (no AIA or no id-ad-ocsp).\n");
        goto EXIT;
    }
    BSL_Buffer *urlBuf = (BSL_Buffer *)BSL_LIST_GetIndexNode(0, urls);
    if (urlBuf == NULL) {
        printf("no OCSP URL found.\n");
        goto EXIT;
    }

    /* The URL list holds raw bytes without a trailing NUL: copy bounded by dataLen. */
    if (urlBuf->dataLen >= sizeof(url)) {
        printf("OCSP URL too long.\n");
        goto EXIT;
    }
    (void)memcpy(url, urlBuf->data, urlBuf->dataLen);
    url[urlBuf->dataLen] = '\0';

    /* Split the URL and resolve the host with getaddrinfo. */
    if (OcspClientParseUrl(url, host, sizeof(host), &port, path, sizeof(path)) != HITLS_PKI_SUCCESS) {
        printf("failed to parse URL: %s\n", url);
        goto EXIT;
    }
    printf("[1] OCSP responder: %s (host=%s, port=%u, path=%s)\n", url, host, (unsigned)port, path);

    (void)snprintf(portStr, sizeof(portStr), "%u", (unsigned)port);
    (void)memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portStr, &hints, &res) != 0 || res == NULL) {
        printf("getaddrinfo failed for %s\n", host);
        goto EXIT;
    }
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        char ip[INET6_ADDRSTRLEN];
        void *addr = ai->ai_family == AF_INET ? (void *)&((struct sockaddr_in *)ai->ai_addr)->sin_addr :
                                                (void *)&((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr;
        if (inet_ntop(ai->ai_family, addr, ip, sizeof(ip)) != NULL) {
            printf("    resolved %s\n", ip);
        }
    }

    /* Open a real non-blocking TCP socket and connect with a bounded wait. */
    fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        printf("socket failed: %s\n", strerror(errno));
        goto EXIT;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        printf("fcntl failed: %s\n", strerror(errno));
        goto EXIT;
    }
    int cr = connect(fd, res->ai_addr, (socklen_t)res->ai_addrlen);
    if (cr != 0 && errno != EINPROGRESS) {
        printf("connect failed: %s\n", strerror(errno));
        goto EXIT;
    }
    if (cr != 0) {
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(fd, &wset);
        struct timeval tv = {OCSP_CLIENT_CONNECT_SEC, 0};
        cr = select(fd + 1, NULL, &wset, NULL, &tv);
        if (cr <= 0) {
            printf("connect timeout.\n");
            goto EXIT;
        }
        int soErr = 0;
        socklen_t soLen = (socklen_t)sizeof(soErr);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soErr, &soLen) != 0 || soErr != 0) {
            printf("connect error: %s\n", strerror(soErr));
            goto EXIT;
        }
    }
    freeaddrinfo(res);
    res = NULL;
    printf("[2] connected to %s via real TCP.\n", host);

    /* Wrap the real fd in a TCP UIO (it takes ownership of the socket). */
    uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    if (uio == NULL || BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, (int32_t)sizeof(fd), &fd) != BSL_SUCCESS) {
        printf("failed to create or configure the TCP UIO.\n");
        goto EXIT;
    }
    BSL_UIO_SetIsUnderlyingClosedByUio(uio, true); /* the UIO closes the socket on free */
    fd = -1; /* ownership moved to the UIO */

    /* Build the OCSP request (one CertID + auto nonce). */
    mdCtx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA1);
    if (mdCtx == NULL) {
        printf("CRYPT_EAL_MdNewCtx failed.\n");
        goto EXIT;
    }
    certId = HITLS_OCSP_CertIdNewFromCert(mdCtx, cert, issuer);
    if (certId == NULL) {
        printf("HITLS_OCSP_CertIdNewFromCert failed.\n");
        goto EXIT;
    }
    singleReq = HITLS_OCSP_SingleReqNew(certId);
    if (singleReq == NULL) {
        printf("HITLS_OCSP_SingleReqNew failed.\n");
        goto EXIT;
    }
    certId = NULL; /* ownership transferred to singleReq */
    req = HITLS_OCSP_ReqNew();
    if (req == NULL) {
        printf("HITLS_OCSP_ReqNew failed.\n");
        goto EXIT;
    }
    if (HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_ADD_SINGLEREQ, (void *)singleReq, sizeof(singleReq)) !=
        HITLS_PKI_SUCCESS) {
        printf("HITLS_OCSP_ReqCtrl ADD_SINGLEREQ failed.\n");
        goto EXIT;
    }
    singleReq = NULL; /* ownership transferred to req */
    (void)HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_SET_NONCE, NULL, 0); /* auto 32-byte random nonce */
    printf("[3] OCSP request (generated):\n");
    (void)OcspClientPrintReq(req);

    /* Send through the OCSP-HTTP adapter (returns a bsl/http ctx; the Host
     * header and timeout are configured via the bsl_http.h API). */
    ctx = HITLS_OCSP_HttpReqCtxNew(uio, path, req);
    if (ctx == NULL) {
        printf("HITLS_OCSP_HttpReqCtxNew failed.\n");
        goto EXIT;
    }
    (void)HITLS_HTTP_ReqCtxAddHeader(ctx, "Host", host);
    uint32_t timeoutSec = OCSP_CLIENT_TIMEOUT_SEC;
    (void)HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_TIMEOUT, &timeoutSec, sizeof(timeoutSec));

    ret = HITLS_OCSP_ERR_IN_PROGRESS;
    for (int32_t tries = 0; tries < OCSP_CLIENT_POLL_TRIES && ret == HITLS_OCSP_ERR_IN_PROGRESS; tries++) {
        ret = HITLS_OCSP_HttpReqCtxExchange(ctx, &resp);
        if (ret == HITLS_OCSP_ERR_IN_PROGRESS) {
            struct timeval sl = {0, OCSP_CLIENT_POLL_MS * 1000};
            (void)select(0, NULL, NULL, NULL, &sl);
        }
    }
    if (ret != HITLS_PKI_SUCCESS || resp == NULL) {
        printf("OCSP exchange failed, ret = 0x%x.\n", (unsigned)ret);
        goto EXIT;
    }
    printf("[4] OCSP response (received):\n");
    (void)OcspClientPrintResp(resp);

    /* Verify the response and extract the certificate status. */
    int32_t respStatus = -1;
    (void)HITLS_OCSP_RespCtrl(resp, HITLS_OCSP_RESP_GET_STATUS, &respStatus, sizeof(respStatus));
    printf("[5] response status: %s\n", HITLS_OCSP_RespStatusToStr(respStatus));
    if (respStatus != HITLS_OCSP_RESP_STATUS_SUCCESSFUL) {
        printf("    no BasicOCSPResponse to check for a non-successful status.\n");
        goto EXIT;
    }

    HITLS_OCSP_BasicResp *bs = NULL;
    (void)HITLS_OCSP_RespCtrl(resp, HITLS_OCSP_RESP_GET_BASIC, &bs, sizeof(&bs));
    if (bs == NULL) {
        printf("no BasicOCSPResponse embedded.\n");
        goto EXIT;
    }

    int32_t nonceStatus = -1;
    (void)HITLS_OCSP_CheckNonce(req, bs, &nonceStatus);
    printf("[6] nonce check    : %s\n", OcspClientNonceStr(nonceStatus));

    /* Verify the SingleResponse answers the requested CertID. */
    HITLS_OCSP_SingleReq *reqSr = NULL;
    HITLS_OCSP_CertId *reqCertId = NULL;
    HITLS_OCSP_SingleResp *single = NULL;
    if (HITLS_OCSP_ReqGetSingleReqByIndex(req, 0, &reqSr) != HITLS_PKI_SUCCESS ||
        HITLS_OCSP_SingleReqGetCertId(reqSr, &reqCertId) != HITLS_PKI_SUCCESS ||
        HITLS_OCSP_BasicRespFindResp(bs, reqCertId, &single) != HITLS_PKI_SUCCESS || single == NULL) {
        printf("[7] SingleResponse matches request : NO (certid not found)\n");
        goto EXIT;
    }
    printf("[7] SingleResponse matches request : yes\n");

    HITLS_OCSP_CertStatus certStatus = HITLS_OCSP_CERT_STATUS_UNKNOWN;
    (void)HITLS_OCSP_SingleRespCtrl(single, HITLS_OCSP_SINGLERESP_GET_CERT_STATUS, &certStatus, sizeof(certStatus));
    printf("[8] cert status    : %s\n", HITLS_OCSP_CertStatusToStr(certStatus));

    int32_t valRet = HITLS_OCSP_CheckValidity(single, OCSP_CLIENT_VALIDITY_DRIFT_SEC, OCSP_CLIENT_VALIDITY_MAXAGE_SEC);
    printf("[9] validity check : %s (ret=0x%x)\n", valRet == HITLS_PKI_SUCCESS ? "ok" : "failed", (unsigned)valRet);

    if (ca != NULL) {
        store = HITLS_X509_StoreCtxNew();
        if (store == NULL) {
            printf("HITLS_X509_StoreCtxNew failed.\n");
            goto EXIT;
        }
        (void)HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, ca, 0);
        /* The live responder signs with the target's issuer CA and does not embed its
         * certificate, so supply the issuer (= signer) as an external cert list. */
        signerCerts = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
        if (signerCerts == NULL || BSL_LIST_AddElement(signerCerts, issuer, BSL_LIST_POS_END) != BSL_SUCCESS) {
            printf("failed to build the signer cert list.\n");
            goto EXIT;
        }
        ret = HITLS_OCSP_BasicRespVerify(bs, signerCerts, store, 0);
        printf("[10] signature verify: %s (ret=0x%x)\n", ret == HITLS_PKI_SUCCESS ? "ok" : "failed", (unsigned)ret);
    }

    /* Optionally dump the raw DER OCSPResponse to a file for a stapling demo. */
    if (outputPath != NULL) {
        BSL_Buffer der = {0};
        if (HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &der) != HITLS_PKI_SUCCESS || der.data == NULL) {
            printf("failed to encode the OCSP response to DER.\n");
            goto EXIT;
        }
        FILE *fp = fopen(outputPath, "wb");
        if (fp == NULL) {
            printf("failed to open output file: %s\n", outputPath);
            BSL_SAL_FREE(der.data);
            goto EXIT;
        }
        (void)fwrite(der.data, 1, der.dataLen, fp);
        (void)fclose(fp);
        printf("wrote %u bytes of DER OCSP response to %s.\n", der.dataLen, outputPath);
        BSL_SAL_FREE(der.data);
    }

    printf("\nOCSP exchange completed.\n");
    rc = 0;
EXIT:
    HITLS_OCSP_RespFree(resp);
    HITLS_OCSP_HttpReqCtxFree(ctx);
    HITLS_OCSP_ReqFree(req);
    HITLS_OCSP_SingleReqFree(singleReq);
    HITLS_OCSP_CertIdFree(certId);
    CRYPT_EAL_MdFreeCtx(mdCtx);
    BSL_UIO_Free(uio);
    if (fd >= 0) {
        (void)BSL_SAL_SockClose(fd);
    }
    BSL_LIST_FREE(signerCerts, (BSL_LIST_PFUNC_FREE)OcspClientNoopFree);
    HITLS_X509_StoreCtxFree(store);
    freeaddrinfo(res);
    BSL_LIST_FREE(urls, (BSL_LIST_PFUNC_FREE)OcspClientFreeUrl);
    HITLS_X509_CertFree(cert);
    HITLS_X509_CertFree(issuer);
    HITLS_X509_CertFree(ca);
    return rc;
}
