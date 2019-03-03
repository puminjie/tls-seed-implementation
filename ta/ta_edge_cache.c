/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define STR_TRACE_USER_TA "EDGE_CACHE"

#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <openssl/ssl.h>
#include <openssl/logs.h>

#include "ta_edge_cache.h"
#include "ta_ec_func.h"
#include "ta_sio.h"
#include "ta_init.h"
#include "ta_cc.h"
#include "ta_debug.h"

//#include "log_client.h"
#include "sys_timer.h"
#include "keypair.h"

static struct tls_manager_st *frontend;
static struct tls_manager_st *backend;
static struct file_manager_st *fmngr;
static struct fetch_broker_st *broker;

TEE_Result TA_CreateEntryPoint(void)
{
  //EDGE_MSG("We create entry point!");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
  //EDGE_MSG("Now we destroy entry point!");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param  params[4], void **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);


	if (param_types != exp_param_types)
    return TEE_ERROR_BAD_PARAMETERS;

	(void)&params;
	(void)&sess_ctx;

	//EDGE_MSG("Our session for edge caching is open!\n");
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	(void)&sess_ctx;
	//EDGE_MSG("Our session for edge caching is ended!\n");
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
  SSL *ssl;
  struct tls_context_record_st *sctx;
  log_t *time_log;
  int ret, sent;
  struct cmd_st *cctx;
  struct bctx_st *rctx;
  struct bctx_st *wctx;
  struct rinfo *r;
  struct buf_st *name;
#ifdef DEBUG
  uint8_t ipb[4];
#endif /* DEBUG */

  (void)&sess_ctx;
  time_log = NULL;

  ret = TEE_SUCCESS;
  rctx = (struct bctx_st *)params[0].memref.buffer;
  wctx = (struct bctx_st *)params[1].memref.buffer;
  cctx = (struct cmd_st *)params[2].memref.buffer;
#ifdef TIME_LOG
  time_log = (log_t *)params[3].memref.buffer;
#endif

#ifdef DEBUG
  if (rctx->ip > 0 && rctx->port > 0)
  {
    ipb[3] = ((rctx->ip) >> 24) & 0xFF;
    ipb[2] = ((rctx->ip) >> 16) & 0xFF;
    ipb[1] = ((rctx->ip) >> 8) & 0xFF;
    ipb[0] = (rctx->ip) & 0xFF;

    //EDGE_LOG("[TA] Received from: %d.%d.%d.%d:%d", ipb[0], ipb[1], ipb[2], ipb[3], rctx->port);
  }
#endif 

  //EDGE_LOG("[TA] Before starting state machine (%d): %s", cmd_id, cmd_to_str(cmd_id));
	switch (cmd_id) {
	case TA_EDGE_CACHE_CMD_INIT:
    init_commands();

    //EDGE_MSG("[TA] Initialize File Manager");
#ifdef TIME_LOG
    init_file_manager(&fmngr, cctx, time_log);
#else
    init_file_manager(&fmngr, cctx, NULL);
#endif /* TIME_LOG */
    //EDGE_MSG("[TA] Initialize TLS frontend Manager");
    init_tls_manager(&frontend, fmngr, TA_FRONTEND_MANAGER);
    //EDGE_MSG("[TA] Initialize TLS backend Manager");
    init_tls_manager(&backend, fmngr, TA_BACKEND_MANAGER);
    //EDGE_MSG("[TA] Initialize Fetch Broker");
#ifdef TIME_LOG
    init_fetch_broker(&broker, frontend, backend, fmngr, time_log);
#else
    init_fetch_broker(&broker, frontend, backend, fmngr, NULL);
#endif /* TIME_LOG */
    //EDGE_MSG("[TA] Initialize all the components");
    cctx->flags = TA_EDGE_CACHE_NXT_GET_DOMAIN;
    name = init_buf_mem(&name, AUTHORITY_NAME, strlen(AUTHORITY_NAME));
    set_address(cctx, name, AUTHORITY_PORT);
    free(name);

    //EDGE_MSG("[TA] End of TA_EDGE_CACHE_CMD_INIT");
    return TEE_SUCCESS;

  case TA_EDGE_CACHE_CMD_GET_DATA_INIT:
    //EDGE_LOG("[TA] Before Back End Operation in DATA_INIT: %s", cmd_to_str(cmd_id));
    ret = get_address(cctx, &name, NULL);
    r = broker->ops->get_by_name(broker, name, PROGRESS_QUEUE)->r;
    sctx = backend->tops->get_tls_context_with_rinfo(backend->tbl, rctx->ip, rctx->port, r, 
        time_log);
    ret = backend->cops->read_io(sctx, rctx, wctx);
    ret = backend->cops->tls_execution(sctx, cctx, backend);
    ret = backend->cops->write_io(sctx, rctx, wctx);
    cctx->flags = TA_EDGE_CACHE_CMD_GET_DATA;
    //EDGE_LOG("[TA] After Back End Operation in DATA_INIT: %s\n", cmd_to_str(cctx->flags));
    return TEE_SUCCESS;

  case TA_EDGE_CACHE_CMD_GET_CC:
  case TA_EDGE_CACHE_CMD_GET_DOMAIN:
  case TA_EDGE_CACHE_CMD_GET_DATA:
    //EDGE_LOG("\n[TA] Before Back End Operation: %s", cmd_to_str(cmd_id));
    sctx = backend->tops->get_tls_context(backend->tbl, rctx->ip, rctx->port, time_log);
    ret = backend->cops->read_io(sctx, rctx, wctx);
    ret = backend->cops->tls_execution(sctx, cctx, backend);
    //EDGE_LOG("[TA] After TLS execution: %d", ret);
    ret = backend->cops->write_io(sctx, rctx, wctx);

    if (sctx->status && sctx->status->finished)
    {
      backend->tops->remove_tls_context(backend->tbl, sctx);
    }
    //EDGE_LOG("[TA] After Back End Operation: %s\n", cmd_to_str(cctx->flags));
    return TEE_SUCCESS;

  case TA_EDGE_CACHE_CMD_TLS:
    //EDGE_LOG("[TA] Before Front End Operation: %s", cmd_to_str(cmd_id));
    //EDGE_LOG("fmngr->head: %p, fmngr->head->ops 2: %p", fmngr->head, fmngr->head->ops);
    sctx = frontend->tops->get_tls_context(frontend->tbl, rctx->ip, rctx->port, time_log);
    ret = frontend->cops->read_io(sctx, rctx, wctx);
    ret = frontend->cops->tls_execution(sctx, cctx, frontend);
    ret = frontend->cops->write_io(sctx, rctx, wctx);
    //EDGE_MSG("[TA] After Front End Operation");
    return TEE_SUCCESS;

  case TA_EDGE_CACHE_CMD_SHUTDOWN:
    //EDGE_LOG("[TA] Before Clear the TLS context: %s", cmd_to_str(cmd_id));
    rctx = (struct bctx_st *)params[0].memref.buffer;
    frontend->tops->shutdown_tls_context(frontend->tbl, rctx->ip, rctx->port); 
    //EDGE_MSG("[TA] After Clear the TLS context");
    return TEE_SUCCESS;

  case TA_EDGE_CACHE_CMD_LOAD:
    //EDGE_LOG("[TA] Before Process the load result: %s", cmd_to_str(cmd_id));
    RECORD_LOG(time_log, BROKER_PROCESS_LOAD_START);
    broker->ops->process_cmd_load(broker, cctx);
    RECORD_LOG(time_log, BROKER_PROCESS_LOAD_END);
    //EDGE_MSG("[TA] After Process the load result");
    return TEE_SUCCESS;

  case TA_EDGE_CACHE_CMD_STORE:
    //EDGE_LOG("[TA] Before Process the store result: %s", cmd_to_str(cmd_id));
    RECORD_LOG(time_log, BROKER_PROCESS_STORE_START);
    broker->ops->process_cmd_store(broker, cctx);
    RECORD_LOG(time_log, BROKER_PROCESS_STORE_END);
    //EDGE_MSG("[TA] After Process the store result");
    return TEE_SUCCESS;

  case TA_EDGE_CACHE_CMD_POLL_DATA:
    //EDGE_LOG("[TA] Before Polling data finished: %s", cmd_to_str(cmd_id));
    RECORD_LOG(time_log, LOG_7);
    sctx = frontend->tops->get_tls_context(frontend->tbl, rctx->ip, rctx->port, time_log);
    RECORD_LOG(time_log, LOG_8);
    sent = frontend->cops->write_io(sctx, rctx, wctx);
    RECORD_LOG(time_log, LOG_9);
    ret = broker->ops->check_finished(broker, frontend, sctx);
    RECORD_LOG(time_log, LOG_10);
    //EDGE_LOG("[TA] CMD_POLL_DATA after check_finished: %d", ret);
    
    if (sctx && sctx->status && sctx->status->finished && sent < BUF_SIZE)
    {
      cctx->flags = TA_EDGE_CACHE_NXT_EXIT;
      RECORD_LOG(time_log, SERVER_SERVE_HTML_END);
      RECORD_LOG(time_log, LOG_11);
      frontend->tops->remove_tls_context(frontend->tbl, sctx);
      RECORD_LOG(time_log, LOG_12);
    }
    else
    {
      //EDGE_MSG("[TA] Not Finished");
      cctx->flags = TA_EDGE_CACHE_NXT_POLL_DATA;
    }
    //EDGE_MSG("[TA] After Polling data finished");
    return TEE_SUCCESS;

  case TA_EDGE_CACHE_CMD_POLL_FETCH:
    //EDGE_LOG("[TA] Before Polling fetch: %s", cmd_to_str(cmd_id));
    broker->ops->poll_request(broker, cctx, WAIT_QUEUE);
    //EDGE_MSG("[TA] After Polling fetch");

    return TEE_SUCCESS;

  case TA_EDGE_CACHE_CMD_POLL_IO:
    //EDGE_LOG("[TA] Before Polling I/O: %s", cmd_to_str(cmd_id));
    broker->ops->poll_request(broker, cctx, WAIT_FILE_QUEUE);
    //EDGE_MSG("[TA] After Polling I/O");

    return TEE_SUCCESS;

  case TA_EDGE_CACHE_CMD_TEST:
#ifdef TIME_LOG
    time_log = (log_t *)params[3].memref.buffer;
    init_test(time_log);
#endif /* TIME_LOG */
    return TEE_SUCCESS;

default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
