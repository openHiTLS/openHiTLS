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
#include <stdint.h>
#include "securec.h"
#include "lock.h"
#include "logger.h"
#include "hitls_func.h"
#include "process.h"
#include "tls_res.h"

#define SUCCESS 0
#define ERROR (-1)

ResList g_ctxList;
ResList g_sslList;

int InitTlsResList(void)
{
    // Initializes the CTX resource management linked list.
    (void)memset_s(&g_ctxList, sizeof(ResList), 0, sizeof(ResList));
    g_ctxList.resListLock = OsLockNew();
    if (g_ctxList.resListLock == NULL) {
        LOG_ERROR("OsLockNew Error");
        return ERROR;
    }
    // Indicates the head element in the linked list, which does not store any resource.
    g_ctxList.res = (Res *)malloc(sizeof(Res));
    if (g_ctxList.res == NULL) {
        OsLockDestroy(g_ctxList.resListLock);
        return ERROR;
    }
    (void)memset_s(g_ctxList.res, sizeof(Res), 0, sizeof(Res));
    g_ctxList.num = 0;

    // Initializing the SSL Resource Management Linked List
    (void)memset_s(&g_sslList, sizeof(ResList), 0, sizeof(ResList));
    g_sslList.resListLock = OsLockNew();
    if (g_sslList.resListLock == NULL) {
        LOG_ERROR("OsLockNew Error");
        free(g_ctxList.res);
        OsLockDestroy(g_ctxList.resListLock);
        g_ctxList.resListLock = NULL;
        return ERROR;
    }
    // Indicates the head element in the linked list, which does not store any resource.
    g_sslList.res = (Res *)malloc(sizeof(Res));
    if (g_sslList.res == NULL) {
        free(g_ctxList.res);
        OsLockDestroy(g_ctxList.resListLock);
        OsLockDestroy(g_sslList.resListLock);
        return ERROR;
    }
    (void)memset_s(g_sslList.res, sizeof(Res), 0, sizeof(Res));
    g_sslList.num = 0;
    return SUCCESS;
}

int InsertResToList(ResList *resList, Res tempRes)
{
    int id;
    Res *curRes = NULL;
    Res *res = (Res*)malloc(sizeof(Res));
    if (res == NULL) {
        return ERROR;
    }
    memset_s(res, sizeof(Res), 0, sizeof(Res));

    // Insert in the lock
    OsLock(resList->resListLock);

    id = resList->num;

    res->ctxId = tempRes.ctxId;
    res->tlsRes = tempRes.tlsRes;
    res->next = NULL;
    res->id = id;
    // In the linked list, the first element is NULL by default and is used as the start element.
    curRes = resList->res->next;
    // When the first element is empty
    if (curRes == NULL) {
        resList->res->next = res;
        resList->num++;
        OsUnLock(resList->resListLock);
        return id;
    }
    // Find the tail element
    while (curRes->next != NULL) {
        curRes = curRes->next;
    }
    curRes->next = res;
    resList->num++;
    OsUnLock(resList->resListLock);
    return id;
}

int InsertCtxToList(void *tlsRes)
{
    ResList *resList = GetCtxList();
    Res ctxRes = {0};
    ctxRes.tlsRes = tlsRes;
    ctxRes.ctxId = -1; // This field is used only in the SSL linked list.
    return InsertResToList(resList, ctxRes);
}

static int GetTlsIdFromResList(ResList *resList, const void *tls)
{
    Res *tlsRes = GetResFromTlsResList(resList, tls);
    if (tlsRes == NULL) {
        LOG_ERROR("GetResFromTlsResList ERROR");
        return ERROR;
    }
    // Indicates the serial number of a resource.
    return tlsRes->id;
}

int InsertSslToList(void *ctx, void *ssl)
{
    int ctxId;
    Res sslRes = {0};
    ResList *ctxList = GetCtxList();
    ResList *sslList = GetSslList();

    ctxId = GetTlsIdFromResList(ctxList, ctx);
    if (ctxId == ERROR) {
        LOG_ERROR("GetTlsIdFromResList Error");
        return ERROR;
    }

    sslRes.tlsRes = ssl;
    sslRes.ctxId = ctxId; // This field is used only in the SSL linked list and indicates the CTX that is created.
    return InsertResToList(sslList, sslRes);
}

ResList *GetCtxList(void)
{
    return &g_ctxList;
}

ResList *GetSslList(void)
{
    return &g_sslList;
}

Res *GetResFromTlsResList(ResList *resList, const void *tlsRes)
{
    Res *tmpRes = NULL;
    OsLock(resList->resListLock);
    // In the linked list, the first element is NULL by default and is used as the start element.
    tmpRes = resList->res->next;
    while (tmpRes != NULL) {
        if (tmpRes->tlsRes == tlsRes) {
            OsUnLock(resList->resListLock);
            return tmpRes;
        }
        tmpRes = tmpRes->next;
    }
    OsUnLock(resList->resListLock);
    return NULL;
}

static Res *GetResFromId(ResList *resList, int id)
{
    Res *tmpRes = NULL;
    OsLock(resList->resListLock);
    // In the linked list, the first element is NULL by default and is used as the start element.
    tmpRes = resList->res->next;
    while (tmpRes != NULL) {
        if (tmpRes->id == id) {
            OsUnLock(resList->resListLock);
            return tmpRes;
        }
        tmpRes = tmpRes->next;
    }
    OsUnLock(resList->resListLock);
    return NULL;
}

void *GetTlsResFromId(ResList *resList, int id)
{
    Res *res = GetResFromId(resList, id);
    if (res == NULL) {
        LOG_ERROR("GetResFromId error");
        return NULL;
    }
    return res->tlsRes;
}

int GetCtxIdFromSsl(const void *tls)
{
    ResList *sslList = GetSslList();
    Res *tmpRes = GetResFromTlsResList(sslList, tls);
    if (tmpRes == NULL) {
        LOG_ERROR("GetResFromTlsResList ERROR");
        return ERROR;
    }
    // CTX ID corresponding to SSL
    return tmpRes->ctxId;
}

static void *GetLastResFromList(ResList *resList)
{
    Res *headRes = resList->res;
    Res *frontRes = NULL;
    Res *nextRes = NULL;

    if (resList->num == 0) {
        return NULL;
    }

    frontRes = headRes->next;
    nextRes = frontRes;
    // Find the last element
    while ((nextRes != NULL) && (nextRes->tlsRes != NULL)) {
        frontRes = nextRes;
        nextRes = frontRes->next;
    }
    resList->num--;
    return frontRes;
}

void FreeResList(ResList *resList)
{
    Res *curRes = NULL;
    Res *tmpRes = NULL;
    OsLock(resList->resListLock);
    curRes = resList->res->next;
    while (curRes != NULL) {
        tmpRes = curRes->next;
        free(curRes);
        curRes = tmpRes;
    }
    OsUnLock(resList->resListLock);
    free(resList->res);
    OsLockDestroy(resList->resListLock);
}

void FreeCtx(TLS_TYPE tlsType, Res *ctxRes)
{
    switch (tlsType) {
        case HITLS:
            HitlsFreeCtx(ctxRes->tlsRes);
            break;
        default:
            /* Unknown type */
            return;
    }
    ctxRes->tlsRes = NULL;
    return;
}

void FreeSsl(TLS_TYPE tlsType, Res *sslRes)
{
    switch (tlsType) {
        case HITLS:
            HitlsFreeSsl(sslRes->tlsRes);
            break;
        default:
            /* Unknown type */
            return;
    }
    sslRes->tlsRes = NULL;
    return;
}

void FreeTlsResList(void)
{
    Process *process = GetProcess();
    TLS_TYPE type = process->tlsType;

    // Clearing CTX Resources
    ResList *ctxList = GetCtxList();
    void *resCtx = GetLastResFromList(ctxList);
    while (resCtx != NULL) {
        FreeCtx(type, resCtx);
        resCtx =  GetLastResFromList(ctxList);
    }
    FreeResList(ctxList);

    // Clearing SSL Resources
    ResList *sslList = GetSslList();
    void *sslRes = GetLastResFromList(sslList);
    while (sslRes != NULL) {
        FreeSsl(type, sslRes);
        sslRes =  GetLastResFromList(sslList);
    }
    FreeResList(sslList);
    return;
}

int FreeResFromSsl(const void *ctx)
{
    Process *process = GetProcess();
    TLS_TYPE type = process->tlsType;
    ResList *sslList = GetSslList();
    Res *preRes = NULL;
    Res *curRes = NULL;
    Res *nextRes = NULL;

    OsLock(sslList->resListLock);
    preRes = sslList->res;
    curRes = sslList->res->next;
    while (curRes != NULL) {
        if (curRes->tlsRes == ctx) {
            nextRes = curRes->next;
            FreeSsl(type, curRes);
            FreeCtx(type, curRes);
            free(curRes);
            preRes->next = nextRes;
            sslList->num--;
            OsUnLock(sslList->resListLock);
            return SUCCESS;
        }
        preRes = curRes;
        curRes = curRes->next;
    }
    OsUnLock(sslList->resListLock);
    return ERROR;
}