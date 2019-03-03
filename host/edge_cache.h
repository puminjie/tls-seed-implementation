#ifndef __EDGE_CACHE_H__
#define __EDGE_CACHE_H__

#include <err.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>
#include <ta_edge_cache.h>

#include <openssl/logs.h>

#include "host_defines.h"
#include "hio.h"

struct ec_ctx 
{
  TEEC_Context ctx;
  TEEC_Session sess;
};

struct forwarder_st
{
  int fd;
  uint8_t close;
  struct ec_ctx *ctx;
  struct hiom_st *iom;
  uint8_t rbuf[BUF_SIZE];
  uint8_t wbuf[BUF_SIZE];
  TEEC_Context *tctx;
  TEEC_Operation op;
};

// Information passed to the thread
struct info
{
  int fd;
  struct ec_ctx *ctx;
  uint32_t ip;
  uint16_t port;
#ifdef TIME_LOG
  uint64_t tcp_start;
  uint64_t tcp_end;
  uint8_t *log_file_name;
#endif /* TIME_LOG */
};

void prepare_tee_session(struct ec_ctx *ctx);
void terminate_tee_session(struct ec_ctx *ctx);

TEEC_Result init_socket(struct forwarder_st *sk[], int fd, struct ec_ctx *ctx, int role,
    void *log);
TEEC_Result prepare_socket(struct forwarder_st *sk, struct cmd_st *cctx, int role);
void free_socket(struct forwarder_st *sk[]);

void network_operation(struct forwarder_st *sk[]);
void file_operation(struct forwarder_st *sk[]);

#endif /* __EDGE_CACHE_H__ */
