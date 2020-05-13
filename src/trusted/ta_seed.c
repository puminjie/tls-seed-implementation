#include <cmds.h>
#include <debug.h>
#include <err.h>

#include "ta_init.h"
#include "ta_sio.h"
#include "ta_debug.h"
#include "ta_ec_func.h"

static tls_manager_t *frontend;
static tls_manager_t *backend;
static file_manager_t *fmngr;

SEED_Result seed_main(uint32_t cmd_id, bctx_t *rctx, bctx_t *wctx, cctx_t *cctx, void *logger)
{
  efstart("cmd_id: %d, rctx: %p, wctx: %p, cctx: %p, logger: %p", cmd_id, rctx, wctx, cctx, logger);
  int ret, tmp;
  tls_context_record_t *sctx;
  buf_t *name;
#ifdef DEBUG
  uint8_t ipb[4];
#endif /* DEBUG */

  ret = SEED_SUCCESS;
  name = NULL;

#ifdef DEBUG
  if (rctx)
  {
    if (rctx->ip > 0 && rctx->port > 0)
    {
      ipb[3] = ((rctx->ip) >> 24) & 0xFF;
      ipb[2] = ((rctx->ip) >> 16) & 0xFF;
      ipb[1] = ((rctx->ip) >> 8) & 0xFF;
      ipb[0] = (rctx->ip) & 0xFF;

      edmsg("Received from: %d.%d.%d.%d:%d", ipb[0], ipb[1], ipb[2], ipb[3], rctx->port);
    }
  }
#endif 

	switch (cmd_id) 
  {
	  case TA_EDGE_CMD_INIT:
      init_commands();

#ifdef TIME_LOG
      init_file_manager(&fmngr, cctx, (logger_t *)logger);
#else
      init_file_manager(&fmngr, cctx, NULL);
#endif /* TIME_LOG */

      init_tls_manager(&frontend, fmngr, cctx->resumption, TA_FRONTEND_MANAGER);
      init_tls_manager(&backend, fmngr, 0, TA_BACKEND_MANAGER);

      cctx->flags = TA_EDGE_NXT_GET_DOMAIN;
      cctx->stage = TA_EDGE_GET_DOMAIN_INIT;
      name = init_alloc_buf_mem(&name, strlen(AUTHORITY_NAME));
      update_buf_mem(name, AUTHORITY_NAME, strlen(AUTHORITY_NAME));
      set_address(cctx, name, AUTHORITY_PORT);
      free(name);
      break;

    case TA_EDGE_CMD_GET_DOMAIN:
    case TA_EDGE_CMD_GET_CC:
#ifdef TIME_LOG
      sctx = backend->tops->get_tls_context(backend->tbl, rctx->ip, rctx->port, 
          cctx, logger); 
#else
      sctx = backend->tops->get_tls_context(backend->tbl, rctx->ip, rctx->port, 
          cctx, NULL); 
#endif /* TIME_LOG */
      backend->cops->read_io(sctx, rctx, wctx);
      backend->cops->tls_execution(sctx, cctx, backend);
      backend->cops->write_io(sctx, rctx, wctx); 
      break;

    case TA_EDGE_CMD_TLS:
    case TA_EDGE_CMD_GET_DATA:
#ifdef TIME_LOG
      sctx = frontend->tops->get_tls_context(frontend->tbl, rctx->ip, rctx->port, 
          cctx, logger);
      if (sctx->start == 0)
      {
        logger_t *l;
        l = (logger_t *)logger;
        if (l->trusted_cpu_func)
          l->log[SEED_LT_SERVER_BEFORE_TLS_ACCEPT].cpu = l->trusted_cpu_func();
        if (l->trusted_time_func)
          l->log[SEED_LT_SERVER_BEFORE_TLS_ACCEPT].time = l->trusted_time_func();
        sctx->start = 1;
      }
#else
      sctx = frontend->tops->get_tls_context(frontend->tbl, rctx->ip, rctx->port, 
          cctx, NULL);
#endif /* TIME_LOG */
      pre_read_operation(sctx, rctx);
      frontend->cops->read_io(sctx, rctx, wctx);
      frontend->cops->tls_execution(sctx, cctx, frontend);
      ret = SEED_SUCCESS;
      tmp = pre_write_operation(sctx, cctx);
      if (tmp < 0)
      {
        frontend->cops->write_io(sctx, rctx, wctx);
        if (SSL_is_init_finished(sctx->ssl))
        {
#ifdef TIME_LOG
          logger_t *l;
          l = (logger_t *)logger;
          if (l->trusted_cpu_func)
            l->log[SEED_LT_SERVER_AFTER_TLS_ACCEPT].cpu = l->trusted_cpu_func();
          if (l->trusted_time_func)
            l->log[SEED_LT_SERVER_AFTER_TLS_ACCEPT].time = l->trusted_time_func();
#endif /* TIME_LOG */
        }
      }
      else
      {
        set_fallback(sctx, cctx);
        frontend->tops->remove_tls_context(frontend->tbl, sctx);
      }
      break;

    case TA_EDGE_CMD_FINISH:
#ifdef TIME_LOG
      sctx = frontend->tops->get_tls_context(frontend->tbl, rctx->ip, rctx->port, 
          cctx, logger);
#else
      sctx = frontend->tops->get_tls_context(frontend->tbl, rctx->ip, rctx->port, 
          cctx, NULL);
#endif /* TIME_LOG */
      ret = frontend->tops->remove_tls_context(frontend->tbl, sctx);
      break;

    case TA_EDGE_CMD_TEST:
      edmsg(">>>> Test <<<<");
      break;

    default:
		  edmsg("default");
      ret = SEED_INVALID_COMMAND;
	}
  
  effinish();
  return ret;
}
