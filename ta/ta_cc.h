#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/logs.h>

#include <tee_api_defines.h>
#include <tee_api_types.h>
#include "ta_sio.h"
#include "ta_file_manager.h"
#include "ta_tls_table.h"

struct io_status_st;

TEE_Result cc_send_request(struct io_status_st *io, struct tls_context_record_st *sctx, 
    struct file_manager_st *mngr, void *data);
TEE_Result cc_parse_data(struct io_status_st *io, uint8_t *msg, uint32_t len);
TEE_Result cc_process_data(struct io_status_st *io, struct tls_context_record_st *sctx, 
    struct file_manager_st *mngr, struct cmd_st *cctx);

int make_software_assertion(SSL *ssl, uint8_t *ec_digest, uint32_t ec_digest_len,
    EVP_PKEY *edge_priv, uint8_t **sa, uint32_t *sa_len);
int make_cc_content_body(unsigned char **cc, EVP_PKEY *orig_pub, EVP_PKEY *ec_pub, 
    const unsigned char *ec_digest, int ec_digest_length, int nid, int *len);
int make_cc_request(unsigned char **request, unsigned char *cc, int cc_len, 
    EVP_PKEY *ec_priv, int nid, int *len);
int make_cc_request_with_verify_cc(unsigned char **request, unsigned char *cc, int cc_len, 
    const unsigned char *ec_digest, int ec_digest_length,
    EVP_PKEY *ec_priv, EVP_PKEY *orig_pub, EVP_PKEY *ec_pub, int nid, int *len);
int make_cc_response(unsigned char **response, unsigned char *request, int req_len, 
    EVP_PKEY *orig_priv, int nid, int *len);
int make_cc_response_with_verify_request(unsigned char **response, unsigned char *request, 
    int req_len, EVP_PKEY *orig_priv, EVP_PKEY *orig_pub, EVP_PKEY *ec_pub, 
    const unsigned char *ec_digest, int ec_digest_length, int nid, int *len);
int make_signature_block(unsigned char **sigblk, unsigned char *msg, int msg_len, 
    EVP_PKEY *priv, int nid, size_t *sigblk_len);

int verify_cc_content_body(unsigned char *content, EVP_PKEY *orig_pub, EVP_PKEY *ec_pub,
    const unsigned char *ec_digest, int ec_digest_length);
int verify_cc_request(unsigned char *request, EVP_PKEY *orig_pub, EVP_PKEY *ec_pub,
    const unsigned char *ec_digest, int ec_digest_length);
int verify_cc_response(unsigned char *response, EVP_PKEY *orig_pub, EVP_PKEY *ec_pub,
    const unsigned char *ec_digest, int ec_digest_length);
int verify_signature(unsigned char *msg, int msg_len, uint16_t sig_type, uint16_t sig_len, 
    unsigned char *sig, EVP_PKEY *pub);
