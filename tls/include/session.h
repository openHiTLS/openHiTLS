/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>
#include <stdbool.h>
#include "sal_time.h"
#include "hitls_session.h"
#include "cert.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_MASTER_KEY_SIZE 256u        /* <= tls1.2 master key is 48 bytes. TLS1.3 can be to 256 bytes. */

/* Increments the reference count for session */
void HITLS_SESS_UpRef(HITLS_Session *sess);

/* Deep copy session */
HITLS_Session *SESS_Copy(HITLS_Session *src);

/* Disable session */
void SESS_Disable(HITLS_Session *sess);

/* set peerCert */
int32_t SESS_SetPeerCert(HITLS_Session *sess, CERT_Pair *peerCert, bool isClient);

/* get peerCert */
int32_t SESS_GetPeerCert(HITLS_Session *sess, CERT_Pair **peerCert);

/* set ticket */
int32_t SESS_SetTicket(HITLS_Session *sess, uint8_t *ticket, uint32_t ticketSize);

/* get ticket */
int32_t SESS_GetTicket(const HITLS_Session *sess, uint8_t **ticket, uint32_t *ticketSize);

/* set hostName */
int32_t SESS_SetHostName(HITLS_Session *sess, uint32_t hostNameSize, uint8_t *hostName);

/* get hostName */
int32_t SESS_GetHostName(HITLS_Session *sess, uint32_t *hostNameSize, uint8_t **hostName);

/* Check the validity of the session */
bool SESS_CheckValidity(HITLS_Session *sess, uint64_t curTime);

/* tls1.3 Checking the Validity of Client Sessions and ObfuscatedTicketAge */
bool SESS_CheckObfuscatedTicketAge(HITLS_Session *sess, uint64_t curTime, uint64_t obfuscatedTicketAge);

uint64_t SESS_GetStartTime(HITLS_Session *sess);

int32_t SESS_SetStartTime(HITLS_Session *sess, uint64_t startTime);

int32_t SESS_SetTicketAgeAdd(HITLS_Session *sess, uint32_t ticketAgeAdd);

uint32_t SESS_GetTicketAgeAdd(const HITLS_Session *sess);

#ifdef __cplusplus
}
#endif

#endif // SESSION_H
