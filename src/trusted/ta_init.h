#ifndef __TA_INIT_H__
#define __TA_INIT_H__

#ifdef PLATFORM_OPTEE
#include <inttypes.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <trace.h>
#endif /* PLATFORM_OPTEE */
#include <openssl/ssl.h>
#ifdef TIME_LOG
  #include <openssl/logger.h>
#endif /* TIME_LOG */
#include "ta_tls_manager.h"
#include "ta_file_manager.h"
#include "ta_tls_context_ops.h"
#include "ta_defines.h"

SEED_Result init_tls_manager(tls_manager_t **mngr, file_manager_t *fmngr, int resumption, 
    int role);
SEED_Result init_file_manager(file_manager_t **mngr, cctx_t *cctx, void *logger);
void init_test(void *tlog);

#endif /* __TA_INIT_H__ */
