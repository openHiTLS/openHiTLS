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
 * Shared include header for the three DTLS 1.3 CID consistency suites
 * (negotiate / update / usage). Each suite .c references it via an
 * INCLUDE_BASE directive so the include set and macros live in one place.
 */

#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include "bsl_bytes.h"
#include "bsl_sal.h"
#include "bsl_uio.h"
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_dtls_cid.h"
#include "hitls_error.h"
#include "hitls_cert_reg.h"
#include "hitls_crypt_type.h"
#include "hitls_crypt_init.h"
#include "hitls_type.h"
#include "tls.h"
#include "hs.h"
#include "hs_ctx.h"
#include "conn_init.h"
#include "frame_tls.h"
#include "frame_msg.h"
#include "simulate_io.h"
#include "parser_frame_msg.h"
#include "pack_frame_msg.h"
#include "frame_io.h"
#include "frame_link.h"
#include "cert.h"
#include "cert_mgr.h"
#include "hs_extensions.h"
#include "hlt_type.h"
#include "hlt.h"
#include "rec_wrapper.h"
#include "process.h"
#include "record.h"
#include "rec_header.h"
#include "alert.h"
#include "bsl_log.h"
#include "cert_callback.h"
#include "dtls_cid.h"

#define READ_BUF_SIZE (18 * 1024)
#define TEMP_DATA_LEN 1024
#define BUF_SIZE_DTO_TEST 18432
