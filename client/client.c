#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <resolv.h>
#include <netdb.h>
#include <pthread.h>
#include <errno.h>
#include <limits.h>
#include <getopt.h>
#include <assert.h>

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/logger.h>
#include <openssl/defines.h>
#include <debug.h>
#include "client.h"

#include <simple_http/simple_https.h>

#include "../src/logger/seed_names.h"
#include "../src/logger/seed_flags.h"

void *run(void *data);
//int open_connection(const char *domain, int port);
SSL_CTX* init_client_ctx(void);
void load_ecdh_params(SSL_CTX *ctx);

int http_make_request(uint8_t *domain, uint32_t dlen, uint8_t *content,
		uint32_t clen, uint8_t *msg, uint32_t *mlen);
int http_parse_response(uint8_t *msg, uint32_t mlen);

unsigned long get_current_time(void);
unsigned long get_current_cpu(void);

void mode_usage()
{
  emsg("    'vanila': the standard TLS client mode");
  emsg("    'seed': the TLS-SEED client mode");
  emsg("    'dc': the TLS-DC client mode");
  emsg("    'keyless': the Keyless SSL client mode");
  emsg("    'mbtls': the mbTLS client mode");
  emsg("    'spx': the SPX client mode");
  emsg("    'tcp': the TCP client mode");
}

void usage(const char *pname)
{
  emsg(">> Usage: %s [options]", pname);
  emsg(">> Options");
  emsg("  -h, --host           hostname");
  emsg("  -s, --name           sni name");
  emsg("  -p, --port           port number");
  emsg("  -l, --log            log prefix");
  emsg("  -d, --log-directory  log directory path");
  emsg("  -n, --log-names      log name path");
  emsg("  -t, --threads        number of threads (default: 1)");
  emsg("  -c, --content        content name (default: 'NULL' for only handshake)");
  emsg("  -r, --resumption");
  emsg("  -m, --mode           'vanila', 'seed', 'dc', 'mbtls', 'spx', 'tcp'");
  mode_usage();
  exit(1);
}

// Client Prototype Implementation
int main(int argc, char *argv[])
{   
  const char *pname, *host, *content, *log_prefix, *log_directory, *msgs, *opt, *tmp, *code;
  const char *name;
	int c, i, err, rc, num_of_threads, port, mode, flags, resumption;
  char *prefix;
  SSL_CTX *ctx;
  arg_t *arg;

  pname = argv[0];
  err = 0;
  host = DEFAULT_HOST_NAME;
  content = NULL;
  code = NULL;
  name = NULL;
  log_prefix = DEFAULT_LOG_PREFIX;
  log_directory = DEFAULT_LOG_DIRECTORY;
  msgs = DEFAULT_LOG_NAME_FILE;
  port = DEFAULT_PORT_NUMBER;
  num_of_threads = DEFAULT_NUM_OF_THREADS;
  resumption = 0;

  mode = CLIENT_MODE_NONE;
  flags = SEED_LF_ALL;

  while (1)
  {
    int opt_idx = 0;
    static struct option long_options[] = {
      {"host", required_argument, 0, 'h'},
      {"name", required_argument, 0, 's'},
      {"port", required_argument, 0, 'p'},
      {"log", required_argument, 0, 'l'},
      {"log-directory", required_argument, 0, 'd'},
      {"log-names", required_argument, 0, 'n'},
      {"threads", required_argument, 0, 't'},
      {"content", required_argument, 0, 'c'},
      {"mode", required_argument, 0, 'm'},
      {"flags", required_argument, 0, 'f'},
      {"resumption", no_argument, 0, 'r'},
      {0, 0, 0, 0}
    };

    opt = "h:s:p:l:d:t:c:m:r0";

    c = getopt_long(argc, argv, opt, long_options, &opt_idx);

    if (c == -1)
      break;

    switch (c)
    {
      case 'h':
        host = optarg;
        break;
      case 's':
        name = optarg;
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'l':
        log_prefix = optarg;
        break;
      case 'd':
        log_directory = optarg;
        break;
      case 'n':
        msgs = optarg;
        if (access(optarg, F_OK) == -1)
          err |= ERR_INVALID_MESSAGES_PATH;
      case 't':
        num_of_threads = atoi(optarg);
        break;
      case 'c':
        content = optarg;
        break;
      case 'm':
        tmp = optarg;
        if (strlen(tmp) == 6 && !strncmp(tmp, "vanila", 6))
        {
          mode = CLIENT_MODE_VANILA;
          code = "vanila";
        }
        else if (strlen(tmp) == 4 && !strncmp(tmp, "seed", 4))
        {
          mode = CLIENT_MODE_SEED;
          code = "seed";
        }
        else if (strlen(tmp) == 2 && !strncmp(tmp, "dc", 2))
        {
          mode = CLIENT_MODE_DC;
          code = "dc";
        }
        else if (strlen(tmp) == 7 && !strncmp(tmp, "keyless", 7))
        {
          mode = CLIENT_MODE_KEYLESS;
          code = "keyless";
        }
        else if (strlen(tmp) == 5 && !strncmp(tmp, "mbtls", 5))
        {
          mode = CLIENT_MODE_MBTLS;
          code = "mbtls";
        }
        else if (strlen(tmp) == 3 && !strncmp(tmp, "spx", 3))
        {
          mode = CLIENT_MODE_SPX;
          code = "spx";
        }
        else if (strlen(tmp) == 3 && !strncmp(tmp, "tcp", 3))
        {
          mode = CLIENT_MODE_TCP;
          code = "tcp";
        }
        else
          err |= ERR_CLIENT_MODE_NONE;
        break;
      case 'f':
        tmp = optarg;
        if (strlen(optarg) == 3 && !strncmp(optarg, "cpu", 3))
        {
          flags = SEED_LF_CPU;
        }
        else if (strlen(optarg) == 4 && !strncmp(optarg, "time", 4))
        {
          flags = SEED_LF_TIME;
        }
        else if (strlen(optarg) == 3 && !strncmp(optarg, "all", 3))
        {
          flags = SEED_LF_ALL;
        }
        break;
      case 'r':
        resumption = 1;
        break;
      default:
        usage(pname);
    }
  }
  
  if (err > 0)
  {
    if (err & ERR_CLIENT_MODE_NONE)
    {
      emsg("You should select the client mode");
    }

    if (err & ERR_INVALID_MESSAGES_PATH)
    {
      emsg("Invalid message file path: %s", msgs);
    }

    usage(pname);
  }

  if (mode == CLIENT_MODE_NONE)
  {
    emsg("You should select the client mode");
    usage(pname);
  }

  if (host)
  {
    imsg("Host: %s", host);
  }

  assert(port > 0 && port < 65536);
  imsg("Port: %d", port);

  if (content)
  {
    imsg("Content: %s", content);
  }
  else
  {
    imsg("Only Handshake");
  }

  if (log_directory)
  {
    imsg("Log Directory: %s", log_directory);
    mkdir(log_directory, 0775);
  }

  if (log_prefix)
  {
    imsg("Log Prefix: %s", log_prefix);
    prefix = (char *)malloc(MAX_FILE_NAME_LEN);
    snprintf(prefix, MAX_FILE_NAME_LEN, "%s_%s", log_prefix, code);
  }

  assert(num_of_threads > 0);
  imsg("Num of threads: %d", num_of_threads);

  imsg("Mode: %s", code);
  imsg("Resumption: %d", resumption);

  assert(flags >= 0);
  imsg("Flags: %d", flags);

	pthread_t thread[num_of_threads];
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	void *status;

  arg = (arg_t *)malloc(sizeof(arg_t));

  if (mode != CLIENT_MODE_TCP)
  {
	  ctx = init_client_ctx();
	  load_ecdh_params(ctx);
  }
  else
    ctx = NULL;

  arg->host = host;
  arg->port = port;
  arg->content = content;
  arg->mode = mode;
  arg->code = code;
  arg->msgs = msgs;
  arg->name = name;
  arg->ctx = ctx;
  arg->flags = flags;
  arg->log_directory = log_directory;
  arg->resumption = resumption;
  if (log_prefix)
    arg->log_prefix = prefix;

	for (i = 0; i < num_of_threads; i++) {
    arg->idx = i;
    rc = pthread_create(&thread[i], &attr, run, arg);

		if (rc) {
			emsg("return code from pthread_create: %d", rc);
			return 1;
		}
	}

	pthread_attr_destroy(&attr);

	for (i = 0; i < num_of_threads; i++) {
		rc = pthread_join(thread[i], &status);

		if (rc) {
			emsg("return code from pthread_join: %d", rc);
			return 1;
		}
	}

	SSL_CTX_free(ctx); /* release context */

	return 0;
}

void *run(void *data)
{	
	int ret, err, server, dlen, clen, rlen, sent, rcvd, region, total = 0, offset = 0;
  unsigned char buf[BUF_SIZE];
  SSL_CTX *ctx;
	SSL *ssl;
  SSL_SESSION *session;
	char request[BUF_SIZE];
#ifdef TIME_LOG
  logger_t *logger;
#endif /* TIME_LOG */
  arg_t *arg;
  http_t *req, *resp;

  arg = (arg_t *)data;
  region = UNTRUSTED;
  session = NULL;
  req = resp = NULL;

  if (arg->mode != CLIENT_MODE_TCP)
  {
    ssl = SSL_new(arg->ctx);   
    if (arg->name)
      SSL_set_tlsext_host_name(ssl, arg->name);
    else
      SSL_set_tlsext_host_name(ssl, arg->host);
  }

  if (arg->mode == CLIENT_MODE_SEED)
    SSL_enable_seed(ssl);
  else if (arg->mode == CLIENT_MODE_DC)
    SSL_enable_dc(ssl);
  else if (arg->mode == CLIENT_MODE_MBTLS)
    SSL_enable_mbtls(ssl);
  
#ifdef TIME_LOG
  logger = init_logger(arg->log_directory, arg->log_prefix, arg->msgs, arg->flags, 
      SEED_UNTRUSTED_LIBRARY);
  set_time_func(logger, region, get_current_time);
  set_cpu_func(logger, region, get_current_cpu);
	SSL_set_time_logger(ssl, logger);
#endif /* TIME_LOG */

	dlen = strlen(arg->host);
  if (arg->content)
  	clen = strlen(arg->content);

  if (arg->content)
  {
    req = init_http_message(HTTP_TYPE_REQUEST);
    if (!req)
    {
      emsg("http request error");
      goto err;
    }

    http_set_version(req, HTTP_VERSION_1_1);
    http_set_method(req, HTTP_METHOD_GET);
    http_set_domain(req, arg->host, strlen(arg->host));
    http_set_default_attributes(req);
    http_set_abs_path(req, arg->content, strlen(arg->content));

    print_header(req);

    resp = init_http_message(HTTP_TYPE_RESPONSE);
    if (!resp)
    {
      emsg("http response error");
      goto err;
    }
  }

  logger->ops->add(logger, SEED_LT_CLIENT_BEFORE_TCP_CONNECT, region);
	server = open_connection(arg->host, arg->port, 1);
  logger->ops->add(logger, SEED_LT_CLIENT_AFTER_TCP_CONNECT, region);

  if (arg->mode != CLIENT_MODE_TCP)
  {
    SSL_set_fd(ssl, server);

    if (session != NULL)
      SSL_set_session(ssl, session);

    logger->ops->add(logger, SEED_LT_CLIENT_BEFORE_TLS_CONNECT, region);
    while (!err)
    {
      ret = SSL_connect(ssl);
      err = process_error(ssl, ret);

      if (err < 0)
      {
        emsg("Failed to SSL connect()");
        ERR_print_errors_fp(stderr);
        goto err;
      }
    }
		logger->ops->add(logger, SEED_LT_CLIENT_AFTER_TLS_CONNECT, region);
		logger->ops->interval(logger, SEED_LT_CLIENT_BEFORE_TCP_CONNECT, 
        SEED_LT_CLIENT_AFTER_TLS_CONNECT);
    imsg("TLS session is established with %s", SSL_get_cipher(ssl));
    printf("TLS session is established with %s\n", SSL_get_cipher(ssl));
    logger->ops->print(logger, SEED_LT_CLIENT_BEFORE_TLS_CONNECT,
        SEED_LT_CLIENT_AFTER_TLS_CONNECT);
  }

  if (arg->content)
  {
    logger->ops->add(logger, SEED_LT_CLIENT_FETCH_HTML_START, region);
    ret = HTTP_NOT_FINISHED;
    while (ret == HTTP_NOT_FINISHED)
      ret = send_https_message(ssl, req);

    if (ret != HTTP_SUCCESS)
    {
      emsg("Send http request error");
      goto err;
    }

    ret = HTTP_NOT_FINISHED;
    while (ret == HTTP_NOT_FINISHED)
      ret = recv_https_message(ssl, resp, NULL);
    if (ret != HTTP_SUCCESS)
    {
      emsg("Receive http response error");
      goto err;
    }
    logger->ops->add(logger, SEED_LT_CLIENT_FETCH_HTML_END, region);
    logger->ops->interval(logger, SEED_LT_CLIENT_BEFORE_TCP_CONNECT, 
        SEED_LT_CLIENT_FETCH_HTML_END);
  }
    
  sleep(0.5);
  if (arg->mode != CLIENT_MODE_TCP)
    SSL_shutdown(ssl);

err: 
  if (logger)
    fin_logger(logger);
	if (ssl) {
		SSL_free(ssl);
		ssl = NULL;
	}
	if (server != -1)
		close(server);

	return NULL;
}

/*
int open_connection(const char *domain, int port)
{   
  int sd, ret;
  struct hostent *host;
  struct sockaddr_in addr;
            
  if ( (host = gethostbyname(domain)) == NULL )
  {
    perror(domain);
    abort();
  }
    
  sd = socket(PF_INET, SOCK_STREAM, 0);
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long*)(host->h_addr);

  if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
  {
    close(sd);
    perror(domain);
    abort();
  }
  
  return sd;
}
*/

SSL_CTX* init_client_ctx(void) {
	SSL_METHOD *method;
	SSL_CTX *ctx;

	SSL_load_error_strings();
	method = (SSL_METHOD *) TLS_client_method();
	ctx = SSL_CTX_new(method);

	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		abort();
	}

  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_verify_depth(ctx, 4);
	SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");

	return ctx;
}


void load_ecdh_params(SSL_CTX *ctx) {
	EC_KEY *ecdh;
	ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

	if (!ecdh)
		perror("Couldn't load the ec key");

	if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1)
		perror("Couldn't set the ECDH parameter (NID_X9_62_prime256v1)");
}

unsigned long get_current_time(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

unsigned long get_current_cpu(void)
{
  struct timespec tp;
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tp);
  return tp.tv_sec * 1000 + tp.tv_nsec / 1000000;
}
