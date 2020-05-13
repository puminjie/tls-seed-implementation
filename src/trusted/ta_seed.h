#ifndef __TA_SEED_H__
#define __TA_SEED_H__

#include <ta_edge.h>
#include "ta_defines.h"
#include "ta_sio.h"

SEED_Result seed_main(uint32_t cmd_id, bctx_t *rctx, bctx_t *wctx, cctx_t *cctx, void *logger);

#endif /* __TA_SEED_H__ */
