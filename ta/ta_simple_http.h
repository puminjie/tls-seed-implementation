#ifndef __TA_SIMPLE_HTTP_H__
#define __TA_SIMPLE_HTTP_H__

#include <inttypes.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <ta_edge_cache.h>
#include "ta_file_manager.h"
#include "ta_ec_func.h"
#include "ta_nio.h"
#include "ta_tls_table.h"

#define BUF_LEN           256
#define INDEX_FILE        "/index.html"
#define INDEX_FILE_LEN    12

#define DELIMITER             "\r\n"
#define DELIMITER_LEN         2

#define DOMAIN_DELIMITER      "\n\n"
#define DOMAIN_DELIMITER_LEN  2

TEE_Result http_send_request(struct io_status_st *io, struct tls_context_record_st *sctx, 
    struct file_manager_st *mngr, struct cmd_st *cctx);
TEE_Result http_send_response(struct io_status_st *io, struct tls_context_record_st *sctx);

TEE_Result http_parse_request(uint8_t *msg, uint32_t mlen, struct rinfo **info);
TEE_Result http_parse_response(struct io_status_st *io, uint8_t *msg, uint32_t mlen);

TEE_Result http_process_data(struct io_status_st *io, struct tls_context_record_st *sctx, 
    struct file_manager_st *mngr, struct cmd_st *cctx);

#endif /* __TA_SIMPLE_HTTP_H__ */
