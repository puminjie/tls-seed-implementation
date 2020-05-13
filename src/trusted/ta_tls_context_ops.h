#ifndef __TA_TLS_CONTEXT_OPS_H__
#define __TA_TLS_CONTEXT_OPS_H__

#include "ta_tls_exec.h"
#include "ta_tls_manager.h"
#include "ta_tls_table.h"

static struct context_ops frontend_ops = 
{
  .init_ctx = init_server_ctx,
  .free_ctx = free_ctx,
  .init_tls_context = init_tls_server_context,
  .free_tls_context = free_tls_context,
  .execute_io = execute_io,
  .read_io = read_io,
  .write_io = write_io,
  .tls_execution = tls_server_execution,
};

static struct context_ops backend_ops = 
{
  .init_ctx = init_client_ctx,
  .free_ctx = free_ctx,
  .init_tls_context = init_tls_client_context,
  .free_tls_context = free_tls_context,
  .execute_io = execute_io,
  .read_io = read_io,
  .write_io = write_io,
  .tls_execution = tls_client_execution,
};

static struct tls_context_table_ops tbl_ops = 
{
  .init_tls_context_table = init_tls_context_table,
  .free_tls_context_table = free_tls_context_table,
  .get_tls_context = get_tls_context,
  .remove_tls_context = remove_tls_context,
  .shutdown_tls_context = shutdown_tls_context,
};

#endif /* __TA_TLS_CONTEXT_OPS_H__ */
