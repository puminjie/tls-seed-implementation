#include "ta_tls_manager.h"
#include "ta_tls_exec.h"
#include "ta_tls_table.h"
#include "ta_defines.h"

TEE_Result init_tls_context_table(struct tls_context_table_st **tbl, struct tls_manager_st *mngr)
{
  int i;

  EDGE_MSG("Initialize tls context table");
  (*tbl) = (struct tls_context_table_st *)malloc(sizeof(struct tls_context_table_st));
  (*tbl)->num_of_contexts = 0;
  for (i=0; i<MAX_RECORDS; i++)
    (*tbl)->record[i] = NULL;
  (*tbl)->manager = mngr;

  return TEE_SUCCESS;
}

void free_tls_context_table(struct tls_context_table_st *tbl)
{
  int i;
  for (i=0; i<tbl->num_of_contexts; i++)
    free(tbl->record[i]);
  free(tbl);
}

struct tls_context_record_st *get_tls_context(struct tls_context_table_st *tbl, 
    uint32_t ip, uint16_t port, log_t *time_log)
{
  struct tls_context_record_st *sctx;
  sctx = NULL;

  EDGE_MSG("[TA] Get TLS context function is called");

  EDGE_LOG("[TA] Number of contexts registered: %d", tbl->num_of_contexts);

  EDGE_LOG("ip: %u, port: %u", ip, port);
  if (ip != 0 && port != 0)
  {
    EDGE_MSG("before find tls context");
    sctx = find_tls_context_from_table(tbl, ip, port);
    EDGE_LOG("after find tls context: %p", sctx);

    if (!sctx)
    {
      EDGE_MSG("[tls-ec] Initialize a new TLS context");
      sctx = register_tls_context_to_table(tbl, ip, port, time_log);
      EDGE_MSG("[tls-ec] Register TLS context to table");
      RECORD_LOG(time_log, SERVER_BEFORE_TLS_ACCEPT);
    }
  }

  EDGE_LOG("Get TLS Context: ret: %p", sctx);
  return sctx;
}

struct tls_context_record_st *get_tls_context_with_rinfo(struct tls_context_table_st *tbl, 
    uint32_t ip, uint16_t port, struct rinfo *r, log_t *time_log)
{
  struct tls_context_record_st *sctx;

  EDGE_MSG("[TA] Get TLS context function is called");

  EDGE_LOG("[TA] Number of contexts registered: %d", tbl->num_of_contexts);

  sctx = get_tls_context(tbl, ip, port, time_log);
  SSL_disable_ec(sctx->ssl);
  EDGE_MSG("[TA] After get record by ssl");
  sctx->status = init_io_status(&(sctx->status), get_ops(TA_EDGE_CACHE_CMD_GET_DATA));
  sctx->status->rinfo = r;
  EDGE_MSG("[TA] Set Rinfo");
  SSL_set_tlsext_host_name(sctx->ssl, r->domain->data);
  EDGE_LOG("[TA] Set host name to %s", r->domain->data);
  //SSL_disable_ec(sctx->ssl);
  //EDGE_MSG("[TA] TLS-EC is disabled");
  sctx->status->flags |= TA_EC_FLAG_RESPONSE_FORWARD;
  EDGE_MSG("");
  EDGE_MSG("");
  EDGE_MSG("[TA] Initialized the flag to TA_EC_FLAG_RESPONSE_FORWARD");
  EDGE_LOG("[TA] sctx: %p, sctx->status: %p", sctx, sctx->status);
  EDGE_MSG("");
  EDGE_MSG("");

  return sctx;
}

struct tls_context_record_st *get_record_by_ssl(struct tls_context_table_st *tbl, SSL *ssl)
{
  struct tls_context_record_st *ret;
  int i;

  ret = NULL;
  for (i=0; i<MAX_RECORDS; i++)
  {
    if (tbl->record[i]->ssl == ssl)
    {
      ret = tbl->record[i];
      break;
    }
  }

  return ret;
}

struct tls_context_record_st *get_record_by_ip_port(struct tls_context_table_st *tbl, 
    uint32_t ip, uint16_t port)
{
  struct tls_context_record_st *ret;
  int i;

  for (i=0; i<MAX_RECORDS; i++)
  {
    if (!(tbl->record[i])) continue;
    if ((tbl->record[i]->sip == ip) == (tbl->record[i]->sport == port))
    {
      EDGE_LOG("[TA] Found the appropriate index: %d", i);
      ret = tbl->record[i];
      break;
    }
  }

  return ret;
}


/** 
 * @brief Find the tls record from the table
 * @param tbl TLS context table
 * @param ip IP address
 * @param port the port number
 * @return TLS context record
 */
struct tls_context_record_st *find_tls_context_from_table(struct tls_context_table_st *tbl,
    uint32_t ip, uint16_t port)
{
  int i;
  struct tls_context_record_st *ret;
  ret = NULL;

  for (i=0; i<MAX_RECORDS; i++)
  {
    if (!(tbl->record[i])) continue;
    if ((tbl->record[i]->sip == ip) && (tbl->record[i]->sport == port))
    {
      ret = tbl->record[i];
    }
  }

  EDGE_MSG("[TA] Before return in find_tls_context_from_table()");
  EDGE_LOG("[TA] sctx in find_tls_context_from_table: %p", ret);
  return ret;
}

/**
 * @brief Find the index number of the tls record in the table
 * @param tbl TLS context table
 * @param ip IP address
 * @param port the port number
 * @return the index number of the TLS record
 */
int find_index_of_tls_context(struct tls_context_table_st *tbl, uint32_t ip, uint16_t port)
{
  int i, ret;

  i = -1;
  
  for (i=0; i<MAX_RECORDS; i++)
  {
    if (!(tbl->record[i])) continue;
    if ((tbl->record[i]->sip == ip) && (tbl->record[i]->sport == port))
    {
      ret = i;
      break;
    }
  }

  return ret;
}

/**
 * @brief Register the tls record into the table
 * @param tbl TLS context table
 * @param ip IP address
 * @param port the port number
 * @param time_log the data structure for the time logging
 * @return TLS context record
 */
struct tls_context_record_st *register_tls_context_to_table(struct tls_context_table_st *tbl,
    uint32_t ip, uint16_t port, log_t *time_log)
{
  EDGE_MSG("Start: register_tls_context_to_table");
  EDGE_LOG("tbl: %p, ip: %d, port: %d, time_log: %p", tbl, ip, port, time_log);

  int idx;

  if ((idx = get_free_index(tbl)) < 0)
  {
    EDGE_MSG("[TA] No free space is left in the tls context table");
    goto err;
  }

  tbl->record[idx] = (struct tls_context_record_st *)
    malloc(sizeof(struct tls_context_record_st));

  if (!tbl->record[idx])
    goto err;
  memset(tbl->record[idx], 0x0, sizeof(struct tls_context_record_st));

  EDGE_LOG("[TA] Registering IP address: %u, Port: %u", ip, port);
  tbl->record[idx]->sip = ip;
  tbl->record[idx]->sport = port;
  tbl->record[idx]->ssl = tbl->manager->cops->init_tls_context(tbl->manager, time_log);
  tbl->record[idx]->status = NULL;
  tbl->num_of_contexts += 1;

  EDGE_LOG("Finished: register_tls_context_to_table");
err:
  return tbl->record[idx];
}

/**
 * @brief Shutdown the TLS context
 * @param tbl TLS context table
 * @param ip IP address
 * @param port the port number
 * @return error code
 */
TEE_Result shutdown_tls_context(struct tls_context_table_st *tbl, uint32_t ip, uint16_t port)
{
  int res;
  TEE_Result ret;
  unsigned char ipb[4];

  ipb[0] = ip & 0xFF;
  ipb[1] = (ip >> 8) & 0xFF;
  ipb[2] = (ip >> 16) & 0xFF;
  ipb[3] = (ip >> 24) & 0xFF;

  ret = TEE_SUCCESS;

  if ((res = SSL_shutdown(find_tls_context_from_table(tbl, ip, port)->ssl)) > 0)
  {
    EDGE_LOG("[TA] The TLS context associated with %d.%d.%d.%d:%d is shutdown", 
        ipb[0], ipb[1], ipb[2], ipb[3], port);
  }
  else if (res == 0)
  {
    EDGE_LOG("[TA] The TLS context associated with %d.%d.%d.%d:%d is not shutdown, yet", 
        ipb[0], ipb[1], ipb[2], ipb[3], port);
  }
  else
  {
    EDGE_LOG("[TA] The TLS context associated with %d.%d.%d.%d:%d is failed", 
        ipb[0], ipb[1], ipb[2], ipb[3], port);
  }

  return ret;
}

/**
 * @brief Free the TLS context record
 * @param sctx the TLS context record to be freed
 */
void free_tls_context_record(struct tls_context_record_st *sctx)
{
  EDGE_LOG("Start: free_tls_context_record: sctx: %p", sctx);

  if (sctx)
  {
    if (sctx->ssl)
    {
      SSL_shutdown(sctx->ssl);
      SSL_free(sctx->ssl);
    }

    if (sctx->status)
    {
      free_io_status(sctx->status);
    }

    free(sctx);
  }
  EDGE_MSG("Finished: free TLS context record end");
}

/**
 * @brief Remove the TLS context from the table
 * @param tbl the TLS context table
 * @param sctx the TLS context to be removed
 * @return SUCCESS/FAILURE
 */
TEE_Result remove_tls_context(struct tls_context_table_st *tbl, 
    struct tls_context_record_st *sctx)
{
  TEE_Result ret;
  int idx;

  EDGE_MSG("[TA] Remove TLS context function is called");

  ret = TEE_SUCCESS;
  EDGE_LOG("[TA] Number of contexts registered: %d", tbl->num_of_contexts);

  EDGE_MSG("Before freeing TLS context record");

  idx = find_index_of_tls_context(tbl, sctx->sip, sctx->sport);
  free_tls_context_record(sctx);
  sctx = NULL;

  if (idx > 0)
  {
    tbl->record[idx] = NULL;
    tbl->num_of_contexts -= 1;
  }

  return ret;
}

/**
 * @brief Get the free index from the table
 * @param tbl The TLS context table
 * @return the free index number
 */
int get_free_index(struct tls_context_table_st *tbl)
{
  int i, idx = -1;

  for (i=0; i<MAX_RECORDS; i++)
  {
    if (!(tbl->record[i]))
    {
      idx = i;
      break;
    }
  }

  return idx;
}
