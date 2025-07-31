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
#ifdef HITLS_BSL_CONF

#include "bsl_uio.h"
#include "bsl_sal.h"
#include "bsl_list.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"
#include "bsl_conf.h"

// Create a conf object based on BSL_CONF_Method
BSL_CONF *BSL_CONF_New(const BSL_CONF_Method *meth)
{
    BSL_CONF *conf = (BSL_CONF *)BSL_SAL_Calloc(1, sizeof(BSL_CONF));
    if (conf == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }
    if (meth == NULL) {
        conf->meth = BSL_CONF_DefaultMethod();
    } else {
        conf->meth = meth;
    }
    if (conf->meth->create == NULL || conf->meth->destroy == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_CONF_INIT_FAIL);
        BSL_SAL_FREE(conf);
        return NULL;
    }
    conf->data = conf->meth->create();
    if (conf->data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        BSL_SAL_FREE(conf);
        return NULL;
    }
    return conf;
}

// release conf resources
void BSL_CONF_Free(BSL_CONF *conf)
{
    if (conf == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return;
    }
    if (conf->meth != NULL && conf->meth->destroy != NULL) {
        conf->meth->destroy(conf->data);
        conf->data = NULL;
    } else {
        BSL_ERR_PUSH_ERROR(BSL_CONF_FREE_FAIL);
    }
    BSL_SAL_FREE(conf);
    return;
}

// Read the conf information from the UIO.
int32_t BSL_CONF_LoadByUIO(BSL_CONF *conf, BSL_UIO *uio)
{
    if (conf == NULL || uio == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (conf->meth != NULL && conf->meth->loadUio != NULL) {
        return conf->meth->loadUio(conf->data, uio);
    } else {
        BSL_ERR_PUSH_ERROR(BSL_CONF_LOAD_FAIL);
        return BSL_CONF_LOAD_FAIL;
    }
}

// Read the conf information from the file.
int32_t BSL_CONF_Load(BSL_CONF *conf, const char *file)
{
    if (conf == NULL || file == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (conf->meth != NULL && conf->meth->load != NULL) {
        return conf->meth->load(conf->data, file);
    } else {
        BSL_ERR_PUSH_ERROR(BSL_CONF_LOAD_FAIL);
        return BSL_CONF_LOAD_FAIL;
    }
}

// Return the BslList that consists of all BslListNodes that store the BSL_CONF_KeyValue with the same section name.
BslList *BSL_CONF_GetSection(const BSL_CONF *conf, const char *section)
{
    if (conf == NULL || section == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return NULL;
    }
    if (conf->meth != NULL && conf->meth->getSection != NULL) {
        return conf->meth->getSection(conf->data, section);
    } else {
        BSL_ERR_PUSH_ERROR(BSL_CONF_GET_FAIL);
        return NULL;
    }
}

// Obtain the value string corresponding to the name in the specified section.
int32_t BSL_CONF_GetString(const BSL_CONF *conf, const char *section, const char *name, char *str, uint32_t *strLen)
{
    if (conf == NULL || section == NULL || name == NULL || str == NULL || strLen == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (conf->meth != NULL && conf->meth->getString != NULL) {
        return conf->meth->getString(conf->data, section, name, str, strLen);
    } else {
        BSL_ERR_PUSH_ERROR(BSL_CONF_GET_FAIL);
        return BSL_CONF_GET_FAIL;
    }
}

// Obtain the integer value corresponding to the name in the specified section.
int32_t BSL_CONF_GetNumber(const BSL_CONF *conf, const char *section, const char *name, long *value)
{
    if (conf == NULL || section == NULL || name == NULL || value == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (conf->meth != NULL && conf->meth->getNumber != NULL) {
        return conf->meth->getNumber(conf->data, section, name, value);
    } else {
        BSL_ERR_PUSH_ERROR(BSL_CONF_GET_FAIL);
        return BSL_CONF_GET_FAIL;
    }
}

// Dump config contents to file.
int32_t BSL_CONF_Dump(const BSL_CONF *conf, const char *file)
{
    if (conf == NULL || file == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (conf->meth != NULL && conf->meth->dump != NULL) {
        return conf->meth->dump(conf->data, file);
    } else {
        BSL_ERR_PUSH_ERROR(BSL_CONF_DUMP_FAIL);
        return BSL_CONF_DUMP_FAIL;
    }
}

// Dump config contents to uio.
int32_t BSL_CONF_DumpUio(const BSL_CONF *conf, BSL_UIO *uio)
{
    if (conf == NULL || uio == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    if (conf->meth != NULL && conf->meth->dumpUio != NULL) {
        return conf->meth->dumpUio(conf->data, uio);
    } else {
        BSL_ERR_PUSH_ERROR(BSL_CONF_DUMP_FAIL);
        return BSL_CONF_DUMP_FAIL;
    }
}

// Get section name array.
char **BSL_CONF_GetSectionNames(const BSL_CONF *conf, uint32_t *namesSize)
{
    if (conf == NULL || namesSize == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return NULL;
    }
    if (conf->meth != NULL && conf->meth->getSectionNames != NULL) {
        return conf->meth->getSectionNames(conf->data, namesSize);
    } else {
        BSL_ERR_PUSH_ERROR(BSL_CONF_GET_FAIL);
        return NULL;
    }
}

#endif /* HITLS_BSL_CONF */
