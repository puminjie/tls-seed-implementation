#ifndef __EDGE_H__
#define __EDGE_H__

#include <openssl/ssl.h>
#ifdef TIME_LOG
  #include <openssl/logger.h>
#endif /* TIME_LOG */

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/dns.h>

#include <setting.h>
#include <mode.h>
#include <domain.h>

#if defined(PLATFORM_OPTEE) || defined(PLATFORM_SGX)
#include <hio.h>
#endif /* PLATFORM_OPTEE or PLATFORM_SGX */

#ifdef PLATFORM_SGX
  #include <sgx_urts.h>
#endif /* PLATFORM_SGX */

#if defined(PLATFORM_OPTEE) || defined(PLATFORM_SGX)
typedef struct forwarder_st
{
  hiom_t *iom;
} forwarder_t;
#endif /* PLATFORM_OPTEE or PLATFORM_SGX */

typedef struct ec_ctx_st
{
#ifdef PLATFORM_VANILA
  SSL_CTX *ctx;
  domain_list_t *list;
#endif /* PLATFORM_VANILA */

#ifdef PLATFORM_SGX
  sgx_enclave_id_t id;
  sgx_launch_token_t token;
#endif /* PLATFORM_SGX */

#ifdef PLATFORM_OPTEE
  TEEC_Context ctx;
  TEEC_Session sess;
#endif /* PLATFORM_OPTEE */

#if defined(PLATFORM_OPTEE) || defined(PLATFORM_SGX)
  forwarder_t *init;
#endif /* PLATFORM_TEE */
} ec_ctx_t;

typedef struct arg_st
{
#ifdef PLATFORM_VANILA
  const char *cert;
  const char *key;
#elif PLATFORM_SGX
  const char *enclave;
#endif /* PLATFORM ARGUMENTS */
  int resumption;
  int mode;
} arg_t;

typedef struct client_st
{
  int idx;
  int bidx;
  int fallback;
  int mode;
  int fclose;
  int bclose;
  int state;
  ec_ctx_t *ctx;
  const char *fb_server;

  struct bufferevent *front;
  struct bufferevent *back;

  void *ptr;
  void *tmp;

#ifdef PLATFORM_VANILA
  SSL *ssl;
#endif /* PLATFORM_VANILA */
  uint8_t *ch;
  int chlen;

#if defined(PLATFORM_OPTEE) || defined(PLATFORM_SGX)
  forwarder_t *frontend;
  forwarder_t *backend;
#endif /* PLATFORM_OPTEE or PLATFORM_SGX */

#ifdef TIME_LOG
  int start;
  logger_t *logger;
#endif /* TIME_LOG */
} client_t;

typedef struct info_st
{
  ec_ctx_t *ctx;
  struct event_base *base;
  const char *log_directory;
  char *log_prefix;
  const char *msgs;
  int mode;
  const char *code;
  const char *fb_server;
  int flags; 
  int context;
} info_t;

struct event_base *g_ebase[MAX_THREADS];
int occupied[MAX_THREADS];

void initialization(void);
void finalization(void);
struct event_base *get_event_base(int *idx);

arg_t *init_arg(void);
#ifdef PLATFORM_VANILA
void arg_set_cert(arg_t *arg, const char *cert);
void arg_set_key(arg_t *arg, const char *key);
#elif PLATFORM_SGX
void arg_set_enclave(arg_t *arg, const char *enclave);
#endif /* PLATFORM ARGUMENT FUNCTIONS */
void arg_set_mode(arg_t *arg, int mode);
void arg_set_resumption(arg_t *arg, int resumption);
void free_arg(arg_t *arg);

ec_ctx_t *init_edge_ctx(arg_t *arg);
void free_edge_ctx(ec_ctx_t *ctx);

client_t *init_client_ctx(info_t *info, struct sockaddr *sa, int idx);
void set_client_fallback(client_t *ctx);
void free_client_ctx(client_t *ctx);

info_t *init_info_ctx(ec_ctx_t *ctx, const char *log_directory, char *log_prefix, 
    const char *label, struct event_base *base, const char *msgs, int flags, int context,
    int mode, const char *code, const char *fb_server);
void free_info_ctx(info_t *ctx);

unsigned long get_current_time(void);
unsigned long get_current_cpu(void);
unsigned int get_current_seconds(void);
int get_address(uint8_t *buf, int len, uint8_t *host, uint16_t *port);

int seed_execution(client_t *client, uint8_t *rbuf, size_t rlen, uint8_t *wbuf, size_t *wlen);
int spx_execution(client_t *client, uint8_t *rbuf, size_t rlen, uint8_t *wbuf, size_t *wlen);
int fallback_execution(client_t *client, uint8_t *rbuf, size_t rlen, 
    uint8_t *wbuf, size_t *wlen);

#endif /* __EDGE_H__ */
