#ifndef __TA_EC_FUNC_H__
#define __TA_EC_FUNC_H__

#include "ta_sio.h"
#include "ta_buf.h"

TEE_Result set_address(struct cmd_st *cctx, struct buf_st *name, uint16_t port);
int get_address(struct cmd_st *cctx, struct buf_st **name, uint16_t *port);

#endif /* __TA_EC_FUNC_H__ */
