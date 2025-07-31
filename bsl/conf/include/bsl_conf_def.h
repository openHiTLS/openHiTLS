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

#ifndef  BSL_CONF_DEF_H
#define  BSL_CONF_DEF_H

#include "hitls_build.h"
#ifdef HITLS_BSL_CONF

#include <stdint.h>
#include "bsl_uio.h"
#include "bsl_list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BSL_CONF_LINE_SIZE 513
#define BSL_CONF_SEC_SIZE 510

typedef struct BslConfDefaultKeyValue {
    char *key;
    char *value;
    uint32_t keyLen;
    uint32_t valueLen;
} BSL_CONF_KeyValue;

typedef struct BslConfDefaultSection {
    BslList *keyValueList;
    char *section;
    uint32_t sectionLen;
} BSL_CONF_Section;

/*  LIST(BslList)_____SECTION1(BSL_CONF_Section)_____LIST(BslList)_______KEY1, VALUE(BSL_CONF_KeyValue)
 *                 |                                                |__KEY2, VALUE(BSL_CONF_KeyValue)
 *                 |                                                |__KEY3, VALUE(BSL_CONF_KeyValue)
 *                 |
 *                 |__SECTION2(BSL_CONF_Section)_____LIST(BslList)_______KEY1, VALUE(BSL_CONF_KeyValue)
 *                 |                                                |__KEY2, VALUE(BSL_CONF_KeyValue)
 *                 ...
 */
typedef BslList *(*BslConfCreate)(void);
typedef void (*BslConfDestroy)(BslList *sectionList);
typedef int32_t (*BslConfLoad)(BslList *sectionList, const char *file);
typedef int32_t (*BslConfLoadUio)(BslList *sectionList, BSL_UIO *uio);
typedef int32_t (*BslConfDump)(BslList *sectionList, const char *file);
typedef int32_t (*BslConfDumpUio)(BslList *sectionList, BSL_UIO *uio);
typedef BslList *(*BslConfGetSection)(BslList *sectionList, const char *section);
typedef int32_t (*BslConfGetString)(BslList *sectionList, const char *section, const char *key,
    char *string, uint32_t *strLen);
typedef int32_t (*BslConfGetNumber)(BslList *sectionList, const char *section, const char *key, long int *num);
typedef char **(*BslConfGetSectionNames)(BslList *sectionList, uint32_t *namesSize);

typedef struct BSL_CONF_MethodStruct {
    BslConfCreate create;
    BslConfDestroy destroy;
    BslConfLoad load;
    BslConfLoadUio loadUio;
    BslConfDump dump;
    BslConfDumpUio dumpUio;
    BslConfGetSection getSection;
    BslConfGetString getString;
    BslConfGetNumber getNumber;
    BslConfGetSectionNames getSectionNames;
} BSL_CONF_Method;

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_CONF */

#endif /* BSL_CONF_DEF_H */