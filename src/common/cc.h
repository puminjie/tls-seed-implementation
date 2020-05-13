#ifndef __CC_H__
#define __CC_H__

#define CC_SUCCESS  1
#define CC_FAILURE  0

#include <edge.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

int cc_send_request(SSL *ssl);
int cc_parse_data(uint8_t *msg, uint32_t len);
int cc_process_data(SSL *ssl, uint8_t *buf, uint32_t len); 

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

int verify_software_assertion(SSL *ssl, uint8_t *sa, EVP_PKEY *edge_pub, uint8_t **ec_digest,
    uint32_t *ec_digest_length);
int verify_cc_content_body(unsigned char *content, EVP_PKEY *orig_pub, EVP_PKEY *ec_pub,
    const unsigned char *ec_digest, int ec_digest_length);
int verify_cc_request(unsigned char *request, EVP_PKEY *orig_pub, EVP_PKEY *ec_pub,
    const unsigned char *ec_digest, int ec_digest_length);
int verify_cc_response(unsigned char *response, EVP_PKEY *orig_pub, EVP_PKEY *ec_pub,
    const unsigned char *ec_digest, int ec_digest_length);
int verify_signature(unsigned char *msg, int msg_len, uint16_t sig_type, uint16_t sig_len, 
    unsigned char *sig, EVP_PKEY *pub);

#endif /* __CC_H__ */
