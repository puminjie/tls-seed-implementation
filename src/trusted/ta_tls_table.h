#ifndef __TA_TLS_TABLE_H__
#define __TA_TLS_TABLE_H__

#include <openssl/ssl.h>
#ifdef TIME_LOG
  #include <openssl/logger.h>
#endif /* TIME_LOG */
#include "ta_types.h"
#include "ta_defines.h"
#include "ta_sio.h"
#include "ta_buf.h"

#ifdef PLATFORM_OPTEE
  #include <inttypes.h>
  #include <tee_internal_api.h>
#endif /* PLATFORM_OPTEE */

typedef struct tls_manager_st tls_manager_t;
typedef struct tls_context_record_st tls_context_record_t;
typedef struct tls_context_table_st
{
  uint16_t num_of_contexts;
  tls_context_record_t *record[MAX_RECORDS];
  tls_manager_t *manager;
} tls_context_table_t;

struct tls_context_record_st
{
  uint32_t sip;                 // IP address related to the session context
  uint16_t sport;               // Port number related to the session context
  SSL *ssl;                     // the TLS session context
  uint8_t *ch;                  // ClientHello
  int chlen;                    // Length of ClientHello
  void *msg;
  int start;
};

SEED_Result init_tls_context_table(tls_context_table_t **tbl, tls_manager_t *mngr);
void free_tls_context_table(tls_context_table_t *tbl);
int get_free_index(tls_context_table_t *tbl);

tls_context_record_t *get_tls_context(tls_context_table_t *tbl, 
    uint32_t ip, uint16_t port, cctx_t *cctx, void *logger);
void free_tls_context_record(struct tls_context_record_st *record);

tls_context_record_t *find_tls_context_from_table(tls_context_table_t *tbl, 
    uint32_t ip, uint16_t port);
tls_context_record_t *register_tls_context_to_table(tls_context_table_t *tbl,
    uint32_t ip, uint16_t port, cctx_t *cctx, void *logger);
SEED_Result remove_tls_context(tls_context_table_t *tbl, tls_context_record_t *sctx);
SEED_Result shutdown_tls_context(tls_context_table_t *tbl, uint32_t ip, uint16_t port);

#endif /* __TA_TLS_TABLE_H__ */
