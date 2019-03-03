#ifndef __TA_TLS_TABLE_H__
#define __TA_TLS_TABLE_H__

#include <inttypes.h>
#include <tee_internal_api.h>
#include <openssl/ssl.h>
#include <openssl/logs.h>
#include "ta_defines.h"
#include "ta_sio.h"
#include "ta_simple_http.h"

struct tls_manager_st;
struct tls_context_table_st
{
  uint16_t num_of_contexts;
  struct tls_context_record_st *record[MAX_RECORDS];
  struct tls_manager_st *manager;
};

struct tls_context_record_st
{
  uint32_t sip;                 // IP address related to the session context
  uint16_t sport;               // Port number related to the session context
  SSL *ssl;                     // the TLS session context
  struct io_status_st *status;  // the status of I/O
};

TEE_Result init_tls_context_table(struct tls_context_table_st **tbl, 
    struct tls_manager_st *mngr);
void free_tls_context_table(struct tls_context_table_st *tbl);
int get_free_index(struct tls_context_table_st *tbl);


struct tls_context_record_st *get_tls_context(struct tls_context_table_st *mngr, uint32_t ip, 
    uint16_t port, log_t *time_log);
struct tls_context_record_st *get_tls_context_with_rinfo(struct tls_context_table_st *mngr, 
    uint32_t ip, uint16_t port, struct rinfo *r, log_t *time_log);
struct tls_context_record_st *get_record_by_ssl(struct tls_context_table_st *tbl, SSL *ssl);
void free_tls_context_record(struct tls_context_record_st *record);

struct tls_context_record_st *find_tls_context_from_table(struct tls_context_table_st *tbl, 
    uint32_t ip, uint16_t port);
struct tls_context_record_st *register_tls_context_to_table(struct tls_context_table_st *tbl,
    uint32_t ip, uint16_t port, log_t *time_log);
TEE_Result remove_tls_context(struct tls_context_table_st *tbl, 
    struct tls_context_record_st *sctx);
TEE_Result shutdown_tls_context(struct tls_context_table_st *tbl, uint32_t ip, uint16_t port);

#endif /* __TA_TLS_TABLE_H__ */
