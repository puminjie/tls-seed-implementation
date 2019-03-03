#ifndef __INIT_H__
#define __INIT_H__

#include "edge_cache.h"
#include "hio.h"

#define AUTHORITY_NAME "www.edgeplatform.com"
#define AUTHORITY_PORT 1234

void init(struct ec_ctx *ctx, void *time_log);

#endif /* __INIT_H__ */
