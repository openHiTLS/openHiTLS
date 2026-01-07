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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <semaphore.h>
#include "hlt_type.h"
#include "securec.h"
#include "logger.h"
#include "rpc_func.h"
#include "channel_res.h"
#include "handle_cmd.h"

#define SUCCESS 0
#define ERROR (-1)
#define ASSERT_RETURN(condition, log) \
    do {                              \
        if (!(condition)) {           \
            LOG_ERROR(log);           \
            return ERROR;             \
        }                             \
    } while (0)

int ExpectResult(CmdData *expectCmdData)
{
    int ret, id;
    char *endPtr = NULL;
    CmdData cmdData;
    ControlChannelRes *channelRes;
    channelRes = GetControlChannelRes();
    OsLock(channelRes->rcvBufferLock);

    id = (int)strtol(expectCmdData->id, &endPtr, 0) % MAX_RCV_BUFFER_NUM;
    // Check whether the corresponding buffer contains content.
    if (strlen(channelRes->rcvBuffer[id]) == 0) {
        OsUnLock(channelRes->rcvBufferLock);
        return ERROR;
    }

    // Parsing the CMD
    ret = ParseCmdFromStr(channelRes->rcvBuffer[id], &cmdData);
    if (ret != SUCCESS) {
        LOG_ERROR("ParseCmdFromStr ERROR");
        OsUnLock(channelRes->rcvBufferLock);
        return ERROR;
    }

    if ((strncmp(expectCmdData->id, cmdData.id, strlen(cmdData.id)) == 0) &&
        (strncmp(expectCmdData->funcId, cmdData.funcId, strlen(cmdData.funcId)) == 0)) {
            ret = memcpy_s(expectCmdData->paras, sizeof(expectCmdData->paras), cmdData.paras, sizeof(cmdData.paras));
            if (ret != EOK) {
                LOG_ERROR("memcpy_s ERROR");
                OsUnLock(channelRes->rcvBufferLock);
                return ERROR;
            }
            (void)memset_s(channelRes->rcvBuffer[id], CONTROL_CHANNEL_MAX_MSG_LEN, 0, CONTROL_CHANNEL_MAX_MSG_LEN);
            OsUnLock(channelRes->rcvBufferLock);
            return SUCCESS;
    }
    OsUnLock(channelRes->rcvBufferLock);
    LOG_ERROR("strncmp ERROR [expectCmdData->id=%s, cmdData.id = %s, expectCmdData->funcId = %s, cmdData.funcId = %s]",
        expectCmdData->id, cmdData.id, expectCmdData->funcId, cmdData.funcId);
    return ERROR;
}

int WaitResultFromPeer(CmdData *expectCmdData)
{
    int ret;
    int tryNum = 0;
    do {
        ret = ExpectResult(expectCmdData);
        usleep(1000); // Waiting for 1000 subtleties
        tryNum++;
    } while ((ret != SUCCESS) && (tryNum < 150000));
    ASSERT_RETURN(ret == SUCCESS, "ExpectResult Error");
    return SUCCESS;
}

int ParseCmdFromStr(char *str, CmdData *cmdData)
{
    int ret, count, strBufLen;
    char *token = NULL;
    char *rest = NULL;
    char *strBuf = NULL;
    (void)memset_s(cmdData, sizeof(CmdData), 0, sizeof(CmdData));

    strBufLen = strlen(str) + 1;
    strBuf = (char*)malloc(strBufLen);
    ASSERT_RETURN(strBuf != NULL, "Malloc Error");
    (void)memset_s(strBuf, strBufLen, 0, strBufLen);
    ret = memcpy_s(strBuf, strBufLen, str, strlen(str));
    if (ret != EOK) {
        LOG_ERROR("memcpy_s Error");
        goto ERR;
    }

    /*
      The command message structure is as follows:
      ID | FUNC | PARAS1 | PARAS2 |......
      Fields are separated by vertical bars (|).
    */
    // Get ID
    token = strtok_s(strBuf, "|", &rest);
    ret = strcpy_s(cmdData->id, sizeof(cmdData->id), token); // Get Id
    if (ret != EOK) {
        LOG_ERROR("strcpy_s Error");
        goto ERR;
    }

    // Get FUNC.
    token = strtok_s(NULL, "|", &rest);
    ret = strcpy_s(cmdData->funcId, sizeof(cmdData->funcId), token); // Get FunId
    if (ret != EOK) {
        LOG_ERROR("strcpy_s Error");
        goto ERR;
    }

    // Obtaining Parameters
    token = strtok_s(NULL, "|", &rest);
    count = 0;
    for (; token != NULL; token = strtok_s(NULL, "|", &rest)) {
        // Maximum length of argument is CONTROL_CHANNEL_MAX_MSG_LEN
        ret = strcpy_s(cmdData->paras[count], sizeof(cmdData->paras[0]), token);
        int offset = 0;
        while (rest[offset] == '|') {
            count++;
            offset++;
        }
        count++;
        if (ret != EOK) {
            break;
        }
    }
    if (ret != EOK) {
        LOG_ERROR("strcpy_s error");
        goto ERR;
    }
    cmdData->parasNum = count;
    free(strBuf);
    return SUCCESS;

ERR:
    free(strBuf);
    return ERROR;
}

int ParseCmdFromBuf(ControlChannelBuf *dataBuf, CmdData *cmdData)
{
    return ParseCmdFromStr(dataBuf->data, cmdData);
}

int ExecuteCmd(CmdData *cmdData)
{
    int ret;
    RpcFunList *rcpFuncList = GetRpcFuncList();
    int funcNum = GetRpcFuncNum();
    ret = ERROR;
    for (int i = 0; i < funcNum; i++) {
        if (strncmp(rcpFuncList[i].funcId, cmdData->funcId, strlen(cmdData->funcId)) == 0) {
            ret = rcpFuncList[i].hfunc(cmdData);
            return ret;
        }
    }
    LOG_ERROR("Not Find FuncId");
    (void)memset_s(cmdData->result, sizeof(cmdData->result), 0, sizeof(cmdData->result));
    ret = sprintf_s(cmdData->result, sizeof(cmdData->result), "%s|%s|%d", cmdData->id, cmdData->funcId, ERROR);
    ASSERT_RETURN(ret > 0, "sprintf_s Error");
    return ret;
}

int ParseCtxConfigFromString(char (*string)[CONTROL_CHANNEL_MAX_MSG_LEN], HLT_Ctx_Config *ctxConfig)
{
    int ret;
    /*
        The message structure is as follows:
        minVersion | maxVersion |cipherSuites |CA |......
        Fields are separated by vertical bars (|).
    */
    int index = 1;
    // minimum version number
    // The first parameter indicates the minimum version number.
    ctxConfig->minVersion = (int)strtol(string[index++], NULL, 10);
    LOG_DEBUG("Remote Process Set Ctx minVersion is %u", ctxConfig->minVersion);

    // Maximum version number
    // The second parameter indicates the maximum version number.
    ctxConfig->maxVersion = (int)strtol(string[index++], NULL, 10);
    LOG_DEBUG("Remote Process Set Ctx maxVersion is %u", ctxConfig->maxVersion);

    // Obtaining the Algorithm Suite
    // The third parameter indicates the algorithm suite.
    ret = strcpy_s(ctxConfig->cipherSuites, sizeof(ctxConfig->cipherSuites), string[index++]);
    ASSERT_RETURN(ret == EOK, "strcpy_s Error");
    LOG_DEBUG("Remote Process Set Ctx cipherSuites is %s", ctxConfig->cipherSuites);

    // The fourth parameter indicates the algorithm suite.
    ret = strcpy_s(ctxConfig->tls13CipherSuites, sizeof(ctxConfig->tls13CipherSuites), string[index++]);
    ASSERT_RETURN(ret == EOK, "strcpy_s Error");
    LOG_DEBUG("Remote Process Set Ctx tls13cipherSuites is %s", ctxConfig->tls13CipherSuites);

    // ECC Point Format Configuration for Asymmetric Algorithms
    // The fifth parameter indicates the dot format.
    ret = strcpy_s(ctxConfig->pointFormats, sizeof(ctxConfig->pointFormats), string[index++]);
    ASSERT_RETURN(ret == EOK, "strcpy_s Error");
    LOG_DEBUG("Remote Process Set Ctx pointFormats is %s", ctxConfig->pointFormats);

    // Obtaining a Group
    // The sixth parameter indicates a group.
    ret = strcpy_s(ctxConfig->groups, sizeof(ctxConfig->groups), string[index++]);
    ASSERT_RETURN(ret == EOK, "strcpy_s Error");
    LOG_DEBUG("Remote Process Set Ctx groups is %s", ctxConfig->groups);

    // Obtaining a Signature
    // The seventh parameter indicates the signature.
    ret = strcpy_s(ctxConfig->signAlgorithms, sizeof(ctxConfig->signAlgorithms), string[index++]);
    ASSERT_RETURN(ret == EOK, "strcpy_s Error");
    LOG_DEBUG("Remote Process Set Ctx signAlgorithms is %s", ctxConfig->signAlgorithms);

    // Whether to support renegotiation
    // The eighth parameter indicates whether renegotiation is supported.
    ctxConfig->isSupportRenegotiation = (((int)strtol(string[index++], NULL, 10)) > 0) ? true : false;
    LOG_DEBUG("Remote Process Set Ctx isSupportRenegotiation is %d", ctxConfig->isSupportRenegotiation);

    // Indicates whether to verify the client.
    // The tenth parameter indicates whether to verify the client.
    ctxConfig->isSupportClientVerify = (((int)strtol(string[index++], NULL, 10)) > 0) ? true : false;
    LOG_DEBUG("Remote Process Set Ctx isSupportClientVerify is %d", ctxConfig->isSupportClientVerify);

    // Indicates whether the client can send an empty certificate chain.
    // The eleventh parameter indicates whether the client can send an empty certificate chain.
    ctxConfig->isSupportNoClientCert = (((int)strtol(string[index++], NULL, 10)) > 0) ? true : false;
    LOG_DEBUG("Remote Process Set Ctx isSupportNoClientCert is %d", ctxConfig->isSupportNoClientCert);

    // Indicates whether extended master keys are supported.
    // The twelfth parameter indicates whether the extended master key is supported.
    ctxConfig->isSupportExtendedMasterSecret = (((int)strtol(string[index++], NULL, 10)) > 0) ? true : false;
    LOG_DEBUG("Remote Process Set Ctx isSupportExtendedMasterSecret is %d", ctxConfig->isSupportExtendedMasterSecret);

    // device certificate
    // The thirteenth parameter indicates the location of the device certificate.
    ret = strcpy_s(ctxConfig->eeCert, sizeof(ctxConfig->eeCert), string[index++]);
    ASSERT_RETURN(ret == EOK, "strcpy_s Error");
    LOG_DEBUG("Remote Process Set Ctx EE is %s", ctxConfig->eeCert);

    // private key
    // The fourteenth parameter indicates the location of the private key.
    ret = strcpy_s(ctxConfig->privKey, sizeof(ctxConfig->privKey), string[index++]);
    ASSERT_RETURN(ret == EOK, "strcpy_s Error");
    LOG_DEBUG("Remote Process Set Ctx privKey is %s", ctxConfig->privKey);

    // private key password
    // The fifteenth parameter indicates the password of the private key.
    ret = strcpy_s(ctxConfig->password, sizeof(ctxConfig->password), string[index++]);
    ASSERT_RETURN(ret == EOK, "strcpy_s Error");
    LOG_DEBUG("Remote Process Set Ctx password is %s", ctxConfig->password);

    // CA certificate
    // The 16th parameter indicates the CA certificate.
    ret = strcpy_s(ctxConfig->caCert, sizeof(ctxConfig->caCert), string[index++]);
    ASSERT_RETURN(ret == EOK, "strcpy_s Error");
    LOG_DEBUG("Remote Process Set Ctx caCert is %s", ctxConfig->caCert);

    // Chain certificate
    // The 17th parameter indicates the certificate chain.
    ret = strcpy_s(ctxConfig->chainCert, sizeof(ctxConfig->chainCert), string[index++]);
    ASSERT_RETURN(ret == EOK, "strcpy_s Error");
    LOG_DEBUG("Remote Process Set Ctx chainCert is %s", ctxConfig->chainCert);

    // signature certificate
    LOG_DEBUG("Remote Process Set Ctx signCert is %s", string[index]);
    // The eighteenth parameter indicates the position of the signature certificate.
    ret = strcpy_s(ctxConfig->signCert, sizeof(ctxConfig->signCert), string[index++]);
    ASSERT_RETURN(ret == EOK, "strcpy_s Error");

    // private key for signature
    LOG_DEBUG("Remote Process Set Ctx signPrivKey is %s", string[index]);
    // The 19th parameter indicates the location of the signature private key.
    ret = strcpy_s(ctxConfig->signPrivKey, sizeof(ctxConfig->signPrivKey), string[index++]);
    ASSERT_RETURN(ret == EOK, "strcpy_s Error");

    // psk
    ret = strcpy_s(ctxConfig->psk, sizeof(ctxConfig->psk), string[index++]); // 21st parameter psk
    ASSERT_RETURN(ret == EOK, "strcpy_s Error");
    LOG_DEBUG("Remote Process Set Ctx psk is %s", ctxConfig->psk);

    // Indicates whether to support session tickets.
    // Indicates whether to enable the sessionTicket function. The value is a decimal number.
    ctxConfig->isSupportSessionTicket = (int)strtol(string[index++], NULL, 10);
    LOG_DEBUG("Remote Process Set Ctx isSupportSessionTicket is %d", ctxConfig->isSupportSessionTicket);

    // Setting the Session Storage Mode
    // The 23rd parameter is used to set the session storage mode. The value is a decimal number.
    ctxConfig->setSessionCache = (int)strtol(string[index++], NULL, 10);
    LOG_DEBUG("Remote Process Set Ctx SessionCache is %d", ctxConfig->setSessionCache);

    // Setting the ticket key cb
    // 24th parameter ticket key cb
    ret = strcpy_s(ctxConfig->ticketKeyCb, sizeof(ctxConfig->ticketKeyCb), string[index++]);
    ASSERT_RETURN(ret == EOK, "strcpy_s Error");
    LOG_DEBUG("Remote Process Set Ctx ticketKeyCb is %s", ctxConfig->ticketKeyCb);

    // Indicates whether isFlightTransmitEnable is supported. The 25th parameter indicates whether to send handshake
    // messages by flight. The value is converted into a decimal number.
    ctxConfig->isFlightTransmitEnable = (((int)strtol(string[index++], NULL, 10)) > 0) ? true : false;
    LOG_DEBUG("Remote Process Set Ctx isFlightTransmitEnable is %d", ctxConfig->isFlightTransmitEnable);

    // Setting the server name
    ret = strcpy_s(ctxConfig->serverName, sizeof(ctxConfig->serverName), string[index++]); // Parameter 26
    ASSERT_RETURN(ret == EOK, "strcpy_s Error");
    LOG_DEBUG("Remote Process Set Ctx ServerName is %s", ctxConfig->serverName);

    // Setting the server name cb
    // 27th parameter server name cb
    ret = strcpy_s(ctxConfig->sniDealCb, sizeof(ctxConfig->sniDealCb), string[index++]);
    ASSERT_RETURN(ret == EOK, "strcpy_s Error");
    LOG_DEBUG("Remote Process Set Ctx ServerNameCb is %s", ctxConfig->sniDealCb);

    // Setting the server name arg
    // 28th parameter server name arg cb
    ret = strcpy_s(ctxConfig->sniArg, sizeof(ctxConfig->sniArg), string[index++]);
    ASSERT_RETURN(ret == EOK, "strcpy_s Error");
    LOG_DEBUG("Remote Process Set Ctx ServerNameArg is %s", ctxConfig->sniArg);

    // Setting the ALPN
    ret = strcpy_s(ctxConfig->alpnList, sizeof(ctxConfig->alpnList), string[index++]); // 29th parameter
    ASSERT_RETURN(ret == EOK, "strcpy_s Error");
    LOG_DEBUG("Remote Process Set Ctx alpnList is %s", ctxConfig->alpnList);

    // Setting the ALPN cb
    ret = strcpy_s(ctxConfig->alpnSelectCb, sizeof(ctxConfig->alpnSelectCb), string[index++]); // 30th parameter
    ASSERT_RETURN(ret == EOK, "strcpy_s Error");
    LOG_DEBUG("Remote Process Set Ctx alpnSelectCb is %s", ctxConfig->alpnSelectCb);

    // Setting the ALPN data
    ret = strcpy_s(ctxConfig->alpnUserData, sizeof(ctxConfig->alpnUserData), string[index++]); // 31th parameter
    ASSERT_RETURN(ret == EOK, "strcpy_s Error");
    LOG_DEBUG("Remote Process Set Ctx alpnUserData is %s", ctxConfig->alpnUserData);

	// Sets the security level. The parameter indicates that the security strength of the key meets the security level
    // requirements and is converted into a decimal number.
    ctxConfig->securitylevel = (int)strtol(string[index++], NULL, 10);
    LOG_DEBUG("Remote Process Set Ctx SecurityLevel is %d", ctxConfig->securitylevel);

    // Indicates whether the DH key length follows the certificate. The parameter indicates whether the DH key length
    // follows the certificate, which is converted into a decimal number.
    ctxConfig->isSupportDhAuto = (int)strtol(string[index++], NULL, 10);
    LOG_DEBUG("Remote Process Set Ctx issupportDhauto is %d", ctxConfig->isSupportDhAuto);

    // Sets the TLS1.3 key exchange mode. The parameter indicates the TLS1.3 key exchange mode,
    // which is converted into a decimal number.
    ctxConfig->keyExchMode = (int)strtol(string[index++], NULL, 10);
    LOG_DEBUG("Remote Process Set Ctx keyExchMode is %u", ctxConfig->keyExchMode);

    // The parameter indicates the SupportType callback type, which converts characters into decimal numbers.
    ctxConfig->SupportType = (int)strtol(string[index++], NULL, 10);
    LOG_DEBUG("Remote Process Set Ctx SupportType is %d", ctxConfig->SupportType);

    ctxConfig->isSupportPostHandshakeAuth = (((int)strtol(string[index++], NULL, 10)) > 0) ? true : false;

    ctxConfig->readAhead = (int)strtol(string[index++], NULL, 10);
    LOG_DEBUG("Remote Process Set Ctx readAhead is %u", ctxConfig->readAhead);
    // Sets whether to verify the keyusage in the certificate. The keyusage is converted into a decimal number.
    ctxConfig->needCheckKeyUsage = (((int)strtol(string[index++], NULL, 10)) > 0) ? true : false;
    LOG_DEBUG("Remote Process Set Ctx needCheckKeyUsage is %d", ctxConfig->needCheckKeyUsage);

    // Set whether to continue the handshake when the verification of peer certificate fails
    ctxConfig->isSupportVerifyNone = (((int)strtol(string[index++], NULL, 10)) > 0) ? true : false;
    LOG_DEBUG("Remote Process Set Ctx isSupportVerifyNone is %d", ctxConfig->isSupportVerifyNone);

    // Whether allow a renegotiation initiated by the client
    ctxConfig->allowClientRenegotiate = (((int)strtol(string[index++], NULL, 10)) > 0) ? true : false;
    LOG_DEBUG("Remote Process Set Ctx allowClientRenegotiate is %d", ctxConfig->allowClientRenegotiate);

    // Set the empty record number.
    ctxConfig->emptyRecordsNum = (int)strtol(string[index++], NULL, 10);
    LOG_DEBUG("Remote Process Set Ctx emptyRecordsNum is %u", ctxConfig->emptyRecordsNum);

    // Whether allow legacy renegotiation
    ctxConfig->allowLegacyRenegotiate = (((int)strtol(string[index++], NULL, 10)) > 0) ? true : false;
    LOG_DEBUG("Remote Process Set Ctx allowLegacyRenegotiate is %d", ctxConfig->allowLegacyRenegotiate);

    // Indicates whether encrypt then mac are supported.
    ctxConfig->isEncryptThenMac = (((int)strtol(string[index++], NULL, 10)) > 0) ? true : false;
    LOG_DEBUG("Remote Process Set Ctx isEncryptThenMac is %d", ctxConfig->isEncryptThenMac);

    // set the features supported by modesupport, The value is a decimal number.
    ctxConfig->modeSupport = (int)strtol(string[index++], NULL, 10);
    LOG_DEBUG("Remote Process Set Ctx modeSupport is %d", ctxConfig->modeSupport);

    ctxConfig->isSupportDtlsCookieExchange = (int)strtol(string[index++], NULL, 10);
    LOG_DEBUG("Remote Process Set Ctx CookieExchange is %d", ctxConfig->isSupportDtlsCookieExchange);

    // Setting the info cb
    ctxConfig->infoCb = NULL; // The pointer cannot be transferred. Set this parameter to null.

    return SUCCESS;
}
