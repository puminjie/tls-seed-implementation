#ifndef __TA_MANAGER_H__
#define __TA_MANAGER_H__
#include <openssl/ssl.h>
#include "ta_sio.h"
#include "ta_nio.h"

#define TA_FRONTEND_MANAGER 1
#define TA_BACKEND_MANAGER  2

struct context_ops;
struct tls_context_table_ops;

/**
 * @brief TLS Manager in the Secure World
 */
struct tls_manager_st 
{
  SSL_CTX *ctx;
  uint8_t *ec_digest;           // the digest of the EC application
  uint16_t ht;                  // the hash algorithm used for the EC digest
  uint32_t len;                 // the length of the EC digest
  struct context_ops *cops;

  struct tls_context_table_st *tbl;
  struct tls_context_table_ops *tops;
  struct file_manager_st *fmngr;
  struct fetch_broker_st *broker;
};

/**
 * @brief TLS Context Operations
 */
struct context_ops
{
  SSL_CTX *(*init_ctx)(struct file_manager_st *mngr);
  void (*free_ctx)(SSL_CTX *ctx);
  SSL *(*init_tls_context)(struct tls_manager_st *mngr, log_t *time_log);
  void (*free_tls_context)(SSL *ssl);
  TEE_Result (*execute_io)(SSL *ssl, struct bctx_st *rctx, struct bctx_st *wctx);
  int (*read_io)(SSL *ssl, struct bctx_st *rctx, struct bctx_st *wctx);
  int (*write_io)(SSL *ssl, struct bctx_st *rctx, struct bctx_st *wctx);
  TEE_Result (*tls_execution)(SSL *ssl, struct cmd_st *cctx, struct tls_manager_st *mngr);
};

/**
 * @brief TLS Context Table Operations
 */
struct tls_context_table_ops
{
  TEE_Result (*init_tls_context_table)(struct tls_context_table_st **tbl, 
      struct tls_manager_st *mngr);
  void (*free_tls_context_table)(struct tls_context_table_st *tbl);

  struct tls_context_record_st *(*get_tls_context)(struct tls_context_table_st *tbl, 
      uint32_t ip, uint16_t port, log_t *time_log);
  struct tls_context_record_st *(*get_tls_context_with_rinfo)(struct tls_context_table_st *tbl, 
      uint32_t ip, uint16_t port, struct rinfo *r, log_t *time_log);
  struct tls_context_record_st *(*get_record_by_ssl)(struct tls_context_table_st *tbl, SSL *ssl);
  TEE_Result (*remove_tls_context)(struct tls_context_table_st *tbl, 
      struct tls_context_record_st *sctx);
  TEE_Result (*shutdown_tls_context)(struct tls_context_table_st *tbl, 
      uint32_t ip, uint16_t port);
};

#endif /* __TA_MANAGER_H__ */
