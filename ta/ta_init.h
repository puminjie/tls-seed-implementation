#ifndef __TA_INIT_H__
#define __TA_INIT_H__

#include <inttypes.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <openssl/ssl.h>
#include <openssl/logs.h>
#include <trace.h>
#include "ta_fetch_broker.h"
#include "ta_tls_context_ops.h"
#include "ta_defines.h"

TEE_Result init_tls_manager(struct tls_manager_st **mngr, 
    struct file_manager_st *fmngr, int role);
TEE_Result init_file_manager(struct file_manager_st **mngr, struct cmd_st *cctx, void *time_log);
TEE_Result init_fetch_broker(struct fetch_broker_st **broker, struct tls_manager_st *front,
    struct tls_manager_st *back, struct file_manager_st *mngr, void *time_log);
void init_test(void *tlog);

#endif /* __TA_INIT_H__ */
