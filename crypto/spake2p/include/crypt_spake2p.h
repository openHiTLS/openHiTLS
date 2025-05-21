/*
 *  Copyright (C) 2024, Your Name or Company
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  SPAKE2+ context structure definition
 */

#ifndef CRYPT_SPAKE2P_H
#define CRYPT_SPAKE2P_H

#include "crypt_local_types.h"
#include "crypt_ecc.h"
#include "crypt_algid.h" /* For CRYPT_PKEY_ParaId, CRYPT_MD_AlgId, CRYPT_MAC_AlgId */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief SPAKE2+ Role
 */
typedef enum {
    CRYPT_SPAKE2P_ROLE_CLIENT,
    CRYPT_SPAKE2P_ROLE_SERVER
} CRYPT_SPAKE2P_Role;

/**
 * \brief   SPAKE2+ context structure
 */
typedef struct {
    CRYPT_SPAKE2P_Role role;    /*!< Role (Client/Server)         */
    CRYPT_PKEY_ParaId curveId;  /*!< Curve ID for the group       */
    CRYPT_MD_AlgId hashId;      /*!< Hash Algorithm ID            */
    CRYPT_MAC_AlgId macId;      /*!< MAC Algorithm ID for KDF     */

    CRYPT_ECC_Grp grp;          /*!< Elliptic curve group         */
    CRYPT_ECC_Point P_generator;/*!< Elliptic curve generator P   */
    CRYPT_ECC_Point M;          /*!< M point (fixed for ciphersuite) */
    CRYPT_ECC_Point N;          /*!< N point (fixed for ciphersuite) */

    unsigned char *pwd_buf;     /*!< Password buffer              */
    size_t pwd_len;             /*!< Password length              */
    CRYPT_MPI pw_scalar;        /*!< Scalar derived from password */

    unsigned char *our_id_buf;  /*!< Our identity buffer          */
    size_t our_id_len;          /*!< Our identity length          */
    unsigned char *peer_id_buf; /*!< Peer's identity buffer       */
    size_t peer_id_len;         /*!< Peer's identity length       */

    CRYPT_MPI w0;               /*!< Scalar w0 (RFC9383)          */
    CRYPT_MPI w1;               /*!< Scalar w1 (RFC9383)          */
    CRYPT_MPI w0_peer;          /*!< Peer's scalar w0 (derived)   */
    CRYPT_MPI w1_peer;          /*!< Peer's scalar w1 (derived)   */

    CRYPT_MPI k_private;        /*!< Our private scalar (x or y)  */
    CRYPT_ECC_Point P_our_msg;  /*!< Our public message point (pU or pV) */
    CRYPT_ECC_Point P_peer_msg; /*!< Peer's public message point (pV or pU) */

    unsigned char *transcript_TT; /*!< Transcript TT                */
    size_t transcript_TT_len;   /*!< Transcript TT length         */

    unsigned char *Ke_derived;  /*!< Derived symmetric key Ke     */
    size_t Ke_derived_len;
    unsigned char *KcA_derived; /*!< Derived MAC key KcA (client) */
    size_t KcA_derived_len;
    unsigned char *KcB_derived; /*!< Derived MAC key KcB (server) */
    size_t KcB_derived_len;

    unsigned char our_mac[CRYPT_MAX_MAC_SIZE]; /*!< Our computed confirmation MAC */
    size_t our_mac_len;
    unsigned char peer_expected_mac[CRYPT_MAX_MAC_SIZE]; /*!< Peer's expected confirmation MAC */
    size_t peer_expected_mac_len;

    /* Temporary storage for points/scalars if needed during complex operations */
    CRYPT_MPI temp_bn1;
    CRYPT_MPI temp_bn2;
    CRYPT_ECC_Point temp_point1;
    CRYPT_ECC_Point temp_point2;
    CRYPT_ECC_Point temp_point3;

} CRYPT_SPAKE2P_Ctx;


/*
 * SPAKE2+ specific control commands for EAL_PkeyCtrl
 * Base value 50 chosen to avoid conflict with existing CRYPT_CTRL_ values.
 */
#define CRYPT_CTRL_SPAKE2P_BASE                       50
#define CRYPT_CTRL_SPAKE2P_INIT_GROUP                 (CRYPT_CTRL_SPAKE2P_BASE + 0)
#define CRYPT_CTRL_SPAKE2P_SET_PASSWORD               (CRYPT_CTRL_SPAKE2P_BASE + 1)
#define CRYPT_CTRL_SPAKE2P_SET_OUR_ID                 (CRYPT_CTRL_SPAKE2P_BASE + 2)
#define CRYPT_CTRL_SPAKE2P_SET_PEER_ID                (CRYPT_CTRL_SPAKE2P_BASE + 3)
#define CRYPT_CTRL_SPAKE2P_SET_ROLE                   (CRYPT_CTRL_SPAKE2P_BASE + 4)
#define CRYPT_CTRL_SPAKE2P_GENERATE_EXCHANGE_MSG      (CRYPT_CTRL_SPAKE2P_BASE + 5)
#define CRYPT_CTRL_SPAKE2P_PROCESS_PEER_MSG_AND_CONFIRM (CRYPT_CTRL_SPAKE2P_BASE + 6)
#define CRYPT_CTRL_SPAKE2P_GET_OUR_CONFIRMATION_MAC   (CRYPT_CTRL_SPAKE2P_BASE + 7)
#define CRYPT_CTRL_SPAKE2P_VERIFY_PEER_CONFIRMATION_MAC (CRYPT_CTRL_SPAKE2P_BASE + 8)
#define CRYPT_CTRL_SPAKE2P_GET_DERIVED_SECRET_KE      (CRYPT_CTRL_SPAKE2P_BASE + 9)

/* For RFC Test Vector Verification */
#define CRYPT_CTRL_SPAKE2P_SET_EPHEMERAL_PRIVATE_KEY  (CRYPT_CTRL_SPAKE2P_BASE + 10) /* val: CRYPT_SPAKE2P_DATA_PARAM (key as hex string or raw bytes) */
#define CRYPT_CTRL_SPAKE2P_GET_COMPUTED_W0            (CRYPT_CTRL_SPAKE2P_BASE + 11) /* val: CRYPT_SPAKE2P_BUFFER_PARAM (w0 as MPI octets) */
#define CRYPT_CTRL_SPAKE2P_GET_COMPUTED_W1            (CRYPT_CTRL_SPAKE2P_BASE + 12) /* val: CRYPT_SPAKE2P_BUFFER_PARAM (w1 as MPI octets) */
#define CRYPT_CTRL_SPAKE2P_GET_EXCHANGE_MESSAGE_RAW   (CRYPT_CTRL_SPAKE2P_BASE + 13) /* val: CRYPT_SPAKE2P_BUFFER_PARAM (P_our_msg as octets, for testing GenerateExchangeMessage output before it's called by user) */
#define CRYPT_CTRL_SPAKE2P_GET_SHARED_POINT_K         (CRYPT_CTRL_SPAKE2P_BASE + 14) /* val: CRYPT_SPAKE2P_BUFFER_PARAM (Shared secret point K = Z = V as octets) */
#define CRYPT_CTRL_SPAKE2P_GET_TRANSCRIPT_TT          (CRYPT_CTRL_SPAKE2P_BASE + 15) /* val: CRYPT_SPAKE2P_BUFFER_PARAM */
#define CRYPT_CTRL_SPAKE2P_GET_DERIVED_SECRET_KCA     (CRYPT_CTRL_SPAKE2P_BASE + 16) /* val: CRYPT_SPAKE2P_BUFFER_PARAM */
#define CRYPT_CTRL_SPAKE2P_GET_DERIVED_SECRET_KCB     (CRYPT_CTRL_SPAKE2P_BASE + 17) /* val: CRYPT_SPAKE2P_BUFFER_PARAM */
#define CRYPT_CTRL_SPAKE2P_GET_PW_SCALAR              (CRYPT_CTRL_SPAKE2P_BASE + 18) /* val: CRYPT_SPAKE2P_BUFFER_PARAM (pw_scalar as MPI octets) */


/* Structure for INIT_GROUP control command */
typedef struct {
    CRYPT_PKEY_ParaId curveId;
    CRYPT_MD_AlgId    hashId;
    CRYPT_MAC_AlgId   macId;
} CRYPT_SPAKE2P_INIT_GROUP_PARAM;

/* Structure for SET_PASSWORD, SET_OUR_ID, SET_PEER_ID, PROCESS_PEER_MSG, VERIFY_PEER_MAC control commands */
typedef struct {
    const uint8_t *data;
    uint32_t       dataLen;
} CRYPT_SPAKE2P_DATA_PARAM;

/* Structure for GENERATE_EXCHANGE_MSG, GET_OUR_CONFIRMATION_MAC, GET_DERIVED_SECRET_KE control commands */
typedef struct {
    uint8_t  *buffer;
    uint32_t *bufferLen; /* In: available size, Out: actual size */
} CRYPT_SPAKE2P_BUFFER_PARAM;


#ifdef __cplusplus
}
#endif

#endif /* CRYPT_SPAKE2P_H */
