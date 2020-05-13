#include "ta_tls_manager.h"
#include "ta_tls_exec.h"
#include "ta_tls_table.h"
#include "ta_defines.h"

#include <debug.h>

/** 
 * @brief Initialize the TLS context table
 * @param tbl TLS context table
 * @param mngr TLS manager
 * @return Error code
 */
SEED_Result init_tls_context_table(tls_context_table_t **tbl, tls_manager_t *mngr)
{
  efstart("tbl: %p, mngr: %p", tbl, mngr);
  assert(tbl != NULL);
  assert(mngr != NULL);

  int i;

  (*tbl) = (tls_context_table_t *)malloc(sizeof(tls_context_table_t));
  memset((*tbl), 0x0, sizeof(tls_context_table_t));
  (*tbl)->num_of_contexts = 0;
  for (i=0; i<MAX_RECORDS; i++)
    (*tbl)->record[i] = NULL;
  (*tbl)->manager = mngr;

  effinish();
  return SEED_SUCCESS;
}

/** 
 * @brief Free the TLS context table
 * @param tbl TLS context table
 * @return Error code
 */
void free_tls_context_table(tls_context_table_t *tbl)
{
  efstart("tbl: %p", tbl);
  assert(tbl != NULL);
  int i;
  for (i=0; i<tbl->num_of_contexts; i++)
    free(tbl->record[i]);
  free(tbl);
  effinish();
}

/** 
 * @brief Get the TLS context from the table
 * @param tbl TLS context table
 * @param ip IP address
 * @param port Port number
 * @return Error code
 */
tls_context_record_t *get_tls_context(tls_context_table_t *tbl, 
    uint32_t ip, uint16_t port, cctx_t *cctx, void *logger)
{
  efstart("tbl: %p, ip: %u, port: %u, cctx: %p, logger: %p", tbl, ip, port, cctx, logger);
  assert(tbl != NULL);
  assert(ip > 0);
  assert(port > 0);

  tls_context_record_t *sctx;
  sctx = NULL;

  edmsg("Number of contexts registered: %d", tbl->num_of_contexts);

  if (ip != 0 && port != 0)
  {
    sctx = find_tls_context_from_table(tbl, ip, port);
    if (!sctx)
    {
      edmsg("Initialize a new TLS context");
      sctx = register_tls_context_to_table(tbl, ip, port, cctx, logger);
      edmsg("Register TLS context to table");
      //RECORD_LOG(time_log, SERVER_BEFORE_TLS_ACCEPT, get_current_time());
    }
  }

  effinish("sctx: %p", sctx);
  return sctx;
}

/** 
 * @brief Find the tls record from the table
 * @param tbl TLS context table
 * @param ip IP address
 * @param port the port number
 * @return TLS context record
 */
tls_context_record_t *find_tls_context_from_table(tls_context_table_t *tbl,
    uint32_t ip, uint16_t port)
{
  efstart("tbl: %p, ip: %u, port: %u", tbl, ip, port);
  assert(tbl != NULL);
  assert(ip > 0);
  assert(port > 0);

  int i;
  tls_context_record_t *ret;
  ret = NULL;

  for (i=0; i<MAX_RECORDS; i++)
  {
    if (!(tbl->record[i])) continue;
    if ((tbl->record[i]->sip == ip) && (tbl->record[i]->sport == port))
    {
      ret = tbl->record[i];
    }
  }

  effinish("ret: %p", ret);
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
  efstart("tbl: %p, ip: %u, port: %u", tbl, ip, port);
  assert(tbl != NULL);
  assert(ip > 0);
  assert(port > 0);

  int i, ret;

  i = -1;
  ret = SEED_SUCCESS;
  
  for (i=0; i<MAX_RECORDS; i++)
  {
    if (!(tbl->record[i])) continue;
    if ((tbl->record[i]->sip == ip) && (tbl->record[i]->sport == port))
    {
      ret = i;
      break;
    }
  }

  effinish("ret: %d", ret);
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
tls_context_record_t *register_tls_context_to_table(tls_context_table_t *tbl,
    uint32_t ip, uint16_t port, cctx_t *cctx, void *logger)
{
  efstart("tbl: %p, ip: %u, port: %u, cctx: %p, logger: %p", tbl, ip, port, cctx, logger);
  assert(tbl != NULL);
  assert(ip > 0);
  assert(port > 0);

  int idx;

  if ((idx = get_free_index(tbl)) < 0)
  {
    eemsg("No free space is left in the tls context table");
    goto err;
  }

  tbl->record[idx] = (tls_context_record_t *)malloc(sizeof(tls_context_record_t));

  if (!tbl->record[idx]) goto err;
  memset(tbl->record[idx], 0x0, sizeof(tls_context_record_t));

  edmsg("Registering IP address: %u, Port: %u", ip, port);
  tbl->record[idx]->sip = ip;
  tbl->record[idx]->sport = port;
  tbl->record[idx]->ssl = tbl->manager->cops->init_tls_context(tbl->manager, cctx, logger);
  tbl->record[idx]->start = 0;
  tbl->num_of_contexts += 1;

  effinish("tbl->record[%d]: %p", idx, tbl->record[idx]);
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
SEED_Result shutdown_tls_context(tls_context_table_t *tbl, uint32_t ip, uint16_t port)
{
  efstart("tbl: %p, ip: %u, port: %u", tbl, ip, port);
  assert(tbl != NULL);
  assert(ip > 0);
  assert(port > 0);

  int res;
  SEED_Result ret;
  unsigned char ipb[4];
  tls_context_record_t *record;
  SSL *ssl;

  ipb[0] = ip & 0xFF;
  ipb[1] = (ip >> 8) & 0xFF;
  ipb[2] = (ip >> 16) & 0xFF;
  ipb[3] = (ip >> 24) & 0xFF;

  ret = SEED_SUCCESS;
  record = find_tls_context_from_table(tbl, ip, port);
  ssl = record->ssl;

  if ((res = SSL_shutdown(ssl)) > 0)
  {
    edmsg("The TLS context associated with %d.%d.%d.%d:%d is shutdown", 
        ipb[0], ipb[1], ipb[2], ipb[3], port);
  }
  else if (res == 0)
  {
    edmsg("The TLS context associated with %d.%d.%d.%d:%d is not shutdown, yet", 
        ipb[0], ipb[1], ipb[2], ipb[3], port);
  }
  else
  {
    eemsg("[TA] The TLS context associated with %d.%d.%d.%d:%d is failed", 
        ipb[0], ipb[1], ipb[2], ipb[3], port);
  }

  effinish();
  return ret;
}

/**
 * @brief Free the TLS context record
 * @param sctx the TLS context record to be freed
 */
void free_tls_context_record(tls_context_record_t *sctx)
{
  efstart("sctx: %p", sctx);

  if (sctx)
  {
    if (sctx->ssl)
    {
      SSL_shutdown(sctx->ssl);
      SSL_free(sctx->ssl);
      sctx->ssl = NULL;
    }

    if (sctx->ch)
    {
      free(sctx->ch);
      sctx->ch = NULL;
    }

    free(sctx);
  }
  effinish();
}

/**
 * @brief Remove the TLS context from the table
 * @param tbl the TLS context table
 * @param sctx the TLS context to be removed
 * @return SUCCESS/FAILURE
 */
SEED_Result remove_tls_context(tls_context_table_t *tbl, tls_context_record_t *sctx)
{
  efstart("tbl: %p, sctx: %p", tbl, sctx);
  assert(tbl != NULL);
  assert(sctx != NULL);

  SEED_Result ret;
  int idx;

  ret = SEED_SUCCESS;
  edmsg("Number of contexts registered: %d", tbl->num_of_contexts);

  idx = find_index_of_tls_context(tbl, sctx->sip, sctx->sport);
  free_tls_context_record(sctx);
  sctx = NULL;

  if (idx >= 0)
  {
    tbl->record[idx] = NULL;
    tbl->num_of_contexts -= 1;
  }

  effinish("ret: %d", ret);
  return ret;
}

/**
 * @brief Get the free index from the table
 * @param tbl The TLS context table
 * @return the free index number
 */
int get_free_index(tls_context_table_t *tbl)
{
  efstart("tbl: %p", tbl);
  assert(tbl != NULL);
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
