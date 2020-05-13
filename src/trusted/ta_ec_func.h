#ifndef __TA_EC_FUNC_H__
#define __TA_EC_FUNC_H__

#include "ta_sio.h"
#include "ta_buf_ops.h"

SEED_Result set_address(cctx_t *cctx, buf_t *name, uint16_t port);
int get_address(cctx_t *cctx, buf_t **name, uint16_t *port);


int pre_read_operation(tls_context_record_t *sctx, bctx_t *rctx);
int pre_write_operation(tls_context_record_t *sctx, cctx_t *cctx);

void set_fallback(tls_context_record_t *sctx, cctx_t *cctx);
/*
void set_fallback_frontend(tls_context_record_t *sctx, fetch_broker_t *broker, cctx_t *cctx);
void set_fallback_backend(cctx_t *cctx, fetch_record_t *record);
*/

#endif /* __TA_EC_FUNC_H__ */
