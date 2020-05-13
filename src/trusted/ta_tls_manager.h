#ifndef __TA_MANAGER_H__
#define __TA_MANAGER_H__
#include <openssl/ssl.h>
#include "ta_sio.h"
#include "ta_defines.h"
#include "ta_file_manager.h"

#define TA_FRONTEND_MANAGER 1
#define TA_BACKEND_MANAGER  2

/**
 * @brief TLS Context Operations
 */
typedef struct context_ops
{
  SSL_CTX *(*init_ctx)(file_manager_t *mngr, int resumption);
  void (*free_ctx)(SSL_CTX *ctx);
  SSL *(*init_tls_context)(tls_manager_t *mngr, cctx_t *cctx, void *logger);
  void (*free_tls_context)(tls_context_record_t *sctx);
  SEED_Result (*execute_io)(tls_context_record_t *sctx, bctx_t *rctx, bctx_t *wctx);
  int (*read_io)(tls_context_record_t *sctx, bctx_t *rctx, bctx_t *wctx);
  int (*write_io)(tls_context_record_t *sctx, bctx_t *rctx, bctx_t *wctx);
  SEED_Result (*tls_execution)(tls_context_record_t *sctx, cctx_t *cctx, tls_manager_t *mngr);
} context_ops_t;

/**
 * @brief TLS Context Table Operations
 */
typedef struct tls_context_table_ops
{
  SEED_Result (*init_tls_context_table)(tls_context_table_t **tbl, tls_manager_t *mngr);
  void (*free_tls_context_table)(tls_context_table_t *tbl);

  tls_context_record_t *(*get_tls_context)(tls_context_table_t *tbl, 
      uint32_t ip, uint16_t port, cctx_t *cctx, void *logger);
  SEED_Result (*remove_tls_context)(tls_context_table_t *tbl, tls_context_record_t *sctx);
  SEED_Result (*shutdown_tls_context)(tls_context_table_t *tbl, uint32_t ip, uint16_t port);
} tls_context_table_ops_t;

/**
 * @brief TLS Manager in the Secure World
 */
typedef struct tls_manager_st 
{
  SSL_CTX *ctx;
  uint8_t *seed_digest;           // the digest of the EC application
  uint16_t ht;                  // the hash algorithm used for the EC digest
  uint32_t len;                 // the length of the EC digest
  context_ops_t *cops;

  tls_context_table_t *tbl;
  tls_context_table_ops_t *tops;

  file_manager_t *fmngr;
} tls_manager_t;

#endif /* __TA_MANAGER_H__ */
