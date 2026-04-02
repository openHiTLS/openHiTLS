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

#ifdef HITLS_BSL_SAL_IP
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include "bsl_err.h"

#define MAX_IPV6_SEGMENT_COUNT 8
#define IPV6_LEN 16
#define IPV4_LEN 4

/*
* Parse IPv4 strings and store their binary to *out
* Success returns true, failure returns false
*/
static bool SAL_ParseIpv4(const char *str, unsigned char *out)
{
    int32_t num = 0;            // The current segment's value
    int32_t digitCount = 0;     // The number of digits in the current segment
    int32_t segIndex = 0;       // Number of segments already stored

    for (int32_t i = 0; ; i++) {
        char c = str[i];

        /* End of segment, check the legality of the current segment */
        if (c == '.' || c == '\0') {
            /*
            * It must contain 4 numerical segments (octets) separated by dots.
            * No segment can be empty (e.g., ".." or addresses starting/ending with a dot are invalid).
            */
            if (digitCount == 0 || segIndex >= 4) {
                return false;
            }

            /* Leading zero check, more than one digit and the first character is' 0 ' */
            if (digitCount > 1 && str[i - digitCount] == '0') {
                return false;
            }

            /* Store the current segment */
            out[segIndex++] = (unsigned char)num;

            if (c == '\0') {
                break;
            }
            
            /* Reset, prepare for the next segment */
            num = 0;
            digitCount = 0;
        } else if (c >= '0' && c <= '9') {
            /* Convert characters to integers using decimal base (10). */
            num = num * 10 + (c - '0');
            /* The value of each segment must be between 0 and 255. */
            if (num > 255) {
                return false;
            }
            /* Each paragraph has a maximum of 3 digits. */
            if (digitCount++ > 3) {
                return false;
            }
        } else {
            /* illegal character */
            return false;
        }
    }

    /* Must be exactly 4 segments */
    return segIndex == 4;
}

/* Find and parse the IPv4 part, return the length of the IPv6 part */
static int32_t FindIpv4(const char *str, uint8_t *ipv4Bytes)
{
    int32_t len = strlen(str);
    int32_t ipv4Start = -1;

    /* Find the last point from back to front and determine the starting position of IPv4 */
    for (int32_t i = len - 1; i >= 0; i--) {
        if (str[i] == '.') {
            int32_t j = i;
            while (j >= 0 && str[j] != ':') {
                j--;
            }
            ipv4Start = j + 1;
            break;
        }
    }

    /* No IPv4 part found, return full length */
    if (ipv4Start < 0) {
        return len;
    }

    const char *ipv4Begin = str + ipv4Start;
    if (!SAL_ParseIpv4(ipv4Begin, ipv4Bytes)) {
        return -1;
    }
    /* Return the length of the IPv6 part (i.e. the number of characters before the start of IPv4) */
    return ipv4Start;
}

static bool IsXdigit(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int32_t CharToDigit(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'z') {
        /* Hexadecimal letters a-f have values 10-15 */
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'Z') {
        /* Hexadecimal letters A-F have values 10-15 */
        return c - 'A' + 10;
    }
    return -1;
}

/* Analyze the hexadecimal segment of IPv6 (excluding IPv4) */
static bool ParseIpv6HexSegments(const char *str, int32_t len, uint16_t *segments, int32_t *segCount, int32_t *dcPos)
{
    int32_t i = 0;
    int32_t currLen = 0;
    uint16_t curr = 0;
    bool inSegment = false;

    while (i < len) {
        char c = str[i];

        if (c != ':') {
            if (!IsXdigit((unsigned char)c)) {
                return false;
            }
            inSegment = true;
            /* Each IPv6 segment can have at most 4 hexadecimal digits */
            if (++currLen > 4) {
                return false;
            }
            int32_t digit = CharToDigit(c);
            /* Left shift by 4 bits for hexadecimal (base-16) */
            curr = (curr << 4) | digit;
            i++;
            continue;
        }
        
        /* Starting with a double colon */
        if (i == 0 && len > 1 && str[1] == ':') {
            *dcPos = 0;
            /* Skip the double colon (2 characters) */
            i += 2;
        } else if (i > 0 && str[i - 1] == ':') {  /* Double colon in the middle */
            /* There can only be one double colon (-1 means not found yet) */
            if (*dcPos != -1) {
                return false;
            }
            *dcPos = *segCount;
            i++;
        } else {
            /* Single colon, end the current paragraph */
            if (!inSegment || *segCount >= MAX_IPV6_SEGMENT_COUNT) {
                /* Empty space or the number of IPv6 segments is over 8 */
                return false;
            }
            segments[(*segCount)++] = curr;
            curr = 0;
            currLen = 0;
            inSegment = false;
            i++;
        }
    }

    /* Process the last segment */
    if (inSegment) {
        if (*segCount >= MAX_IPV6_SEGMENT_COUNT) {
            return false;
        }
        segments[(*segCount)++] = curr;
    }

    return true;
}

/* Expand into 8 complete 16 bit segments */
static bool ExpandSegments(const uint16_t *segments, int32_t segCount, int32_t dcPos,
    uint8_t *ipv4Bytes, uint16_t *final)
{
    int32_t total = MAX_IPV6_SEGMENT_COUNT;
    /* IPv4 partially occupies 2 segments */
    int32_t ipv4Segs = (ipv4Bytes != NULL) ? 2 : 0;
    /* Number of non-zero segments */
    int32_t nonZero = segCount + ipv4Segs;

    /* The IPv6 contains double colons */
    if (dcPos != -1) {
        if (nonZero >= total) {
            return false;
        }
        int32_t zeroSegs = total - nonZero;

        /* Copy the segment before the double colon */
        for (int32_t i = 0; i < dcPos; i++) {
            final[i] = segments[i];
        }

        /* Zero padding */
        for (int32_t i = dcPos; i < dcPos + zeroSegs; i++) {
            final[i] = 0;
        }

        /* Copy the segment after the double colon */
        int32_t after = dcPos + zeroSegs;
        for (int32_t i = 0; i < segCount - dcPos; i++) {
            final[after + i] = segments[dcPos + i];
        }

        /* Add IPv4 segment (last two positions) */
        if (ipv4Segs > 0) {
            /* Combine first two IPv4 bytes(0 and 1) into one 16-bit segment (left shift by 8) */
            final[after + (segCount - dcPos)] = (ipv4Bytes[0] << 8) | ipv4Bytes[1];
            /* Combine last two IPv4 bytes(2 and 3) into one 16-bit segment (left shift by 8) */
            final[after + (segCount - dcPos) + 1] = (ipv4Bytes[2] << 8) | ipv4Bytes[3];
        }
    } else {
        /* The IPv6 does not contain double colons */
        if (nonZero != total) {
            return false;
        }

        for (int32_t i = 0; i < segCount; i++) {
            final[i] = segments[i];
        }

        if (ipv4Segs > 0) {
            /* The sixth paragraph is comes from the first two IPv4 bytes(0 and 1) */
            final[6] = (ipv4Bytes[0] << 8) | ipv4Bytes[1];
            /* The seventh paragraph is comes from the last two IPv4 bytes(2 and 3) */
            final[7] = (ipv4Bytes[2] << 8) | ipv4Bytes[3];
        }
    }
    return true;
}

static bool SAL_ParseIpv6(const char *str, unsigned char *out)
{
    int32_t len = strlen(str);
    /* Check if it ends with a single colon */
    if (len > 0 && str[len - 1] == ':') {
        if (len == 1 || str[len - 1 - 1] != ':') {
            return false;
        }
    }

    uint8_t ipv4Bytes[4] = {0};
    int32_t ipv6Len = FindIpv4(str, ipv4Bytes);
    if (ipv6Len < 0) {
        return false;
    }

    bool hasIpv4 = (ipv6Len < (int32_t)strlen(str));

    uint16_t segments[MAX_IPV6_SEGMENT_COUNT];
    int32_t segCount = 0;
    int32_t dcPos = -1;
    if (!ParseIpv6HexSegments(str, ipv6Len, segments, &segCount, &dcPos)) {
        return false;
    }

    uint16_t final[MAX_IPV6_SEGMENT_COUNT];
    if (!ExpandSegments(segments, segCount, dcPos, hasIpv4 ? ipv4Bytes : NULL, final)) {
        return false;
    }

    for (int32_t i = 0; i < MAX_IPV6_SEGMENT_COUNT; i++) {
        /* High byte: shift right by 8 bits and mask with 0xFF, i*2 is output index */
        out[i * 2]   = (final[i] >> 8) & 0xFF;
        /* Low byte: mask with 0xFF to get the lower 8 bits, i*2+1 is output index */
        out[i * 2 + 1] = final[i] & 0xFF;
    }
    return true;
}

int32_t SAL_ParseIp(const char *str, unsigned char *out, int32_t *outLen)
{
    if (str == NULL || out == NULL || outLen == NULL) {
        return BSL_NULL_INPUT;
    }

    if (strchr(str, ':')) {
        if (*outLen < IPV6_LEN) {
            return BSL_INVALID_ARG;
        }
        if (SAL_ParseIpv6(str, out)) {
            *outLen = IPV6_LEN;
            return BSL_SUCCESS;
        }
    } else {
        if (*outLen < IPV4_LEN) {
            return BSL_INVALID_ARG;
        }
        if (SAL_ParseIpv4(str, out)) {
            *outLen = IPV4_LEN;
            return BSL_SUCCESS;
        }
    }

    *outLen = 0;
    return BSL_INVALID_ARG;
}
#endif // HITLS_BSL_SAL_IP