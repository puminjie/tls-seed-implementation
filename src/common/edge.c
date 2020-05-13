#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
# ifdef _XOPEN_SOURCE_EXTENDED
#  include <arpa/inet.h>
# endif
#include <sys/socket.h>
#include <sys/stat.h>
#include <getopt.h>

#include <event2/listener.h>
#include <edge.h>
#include <debug.h>
#include <defines.h>
#include <err.h>

#include <stdio.h>
#include <assert.h>

#ifdef TIME_LOG
#include "../logger/seed_logger.h"
#endif /* TIME_LOG */

static void listener_cb(struct evconnlistener *, evutil_socket_t,
    struct sockaddr *, int socklen, void *);
static void conn_readcb(struct bufferevent *, void *);
static void conn_eventcb(struct bufferevent *, short, void *);
static void signal_cb(evutil_socket_t, short, void *);

void mode_usage()
{
  emsg("      'vanila': the standard TLS mode (SplitTLS)");
  emsg("      'seed': the TLS-SEED edge mode");
  emsg("      'dc': the TLS-DC edge mode");
  emsg("      'keyless': the Keyless SSL edge mode");
  emsg("      'mbtls': the mbTLS middlebox mode");
  emsg("      'spx': the SPX edge mode");
  emsg("      'tcp': the TCP edge mode");
}

int usage(const char *pname)
{
  emsg(">> Usage: %s [options]", pname);
  emsg("Options");
  emsg("  -l, --log            log prefix");
  emsg("  -d, --log-directory  log directory path");
  emsg("  -p, --port           port number");
  emsg("  -a, --label          label of the log file");
  emsg("  -n, --log-names      file path that includes log names");
  emsg("  -f, --flags          'cpu', 'time', 'all'");
#ifdef PLATFORM_VANILA
  emsg("  -c, --cert           certificate file");
  emsg("  -k, --key            private key file");
#elif PLATFORM_OPTEE
#elif PLATFORM_SGX
  emsg("  -e, --enclave        enclave file");
#endif /* PLATFORM_VANILA */
  emsg("  -m, --mode           'vanila', 'seed', 'dc', 'mbtls', 'spx', 'tcp'");
  mode_usage();
  emsg("  -s, --server         'vanila', 'mbtls', 'spx'");
  emsg("  -b, --fallback       fallback server name");
  emsg("  -r, --resumption");
  exit(1);
}

int
main(int argc, char **argv)
{
	struct event_base *base;
	struct evconnlistener *listener;
	struct event *signal_event;
  
	struct sockaddr_in sin;

  arg_t *arg;
  ec_ctx_t *ctx;
  info_t *info;
  
  int c, port, err, flags, context, mode, resumption;
  const char *pname;
  const char *log_directory;
  const char *log_prefix;
  const char *label;
  const char *msgs;
  const char *code;
  const char *tmp;
  const char *fb_server;
#ifdef PLATFORM_VANILA
  const char *cert;
  const char *key;
#elif PLATFORM_SGX
  const char *enclave;
#endif /* PLATFORM ARGUMENTS */
  char *prefix;

  arg = NULL;
  ctx = NULL;
  info = NULL;
  prefix = NULL;

  pname = argv[0];
  err = 0;
  port = DEFAULT_PORT_NUMBER;
  log_directory = DEFAULT_LOG_DIRECTORY;
  log_prefix = DEFAULT_LOG_PREFIX;
  label = NULL;
  msgs = NULL;
  flags = -1;
#ifdef PLATFORM_VANILA
  cert = DEFAULT_CERT_PATH;
  key = DEFAULT_KEY_PATH;
#elif PLATFORM_SGX
  enclave = DEFAULT_ENCLAVE_PATH;
#endif /* PLATFORM_VANILA */
  mode = EDGE_MODE_NONE;
  code = NULL;
  resumption = 0;

#ifdef PLATFORM_VANILA
  context = SEED_UNTRUSTED_LIBRARY;
#else
  context = SEED_TRUSTED_LIBRARY;
#endif /* PLATFORM_VANILA */

  /* Get the command line arguments */
  while (1)
  {
    int option_index = 0;
    static struct option long_options[] = {
      {"log", required_argument, 0, 'l'},
      {"log-directory", required_argument, 0, 'd'},
      {"port", required_argument, 0, 'p'},
      {"lable", required_argument, 0, 'a'},
      {"log-names", required_argument, 0, 'n'},
      {"flags", required_argument, 0, 'f'},
#ifdef PLATFORM_VANILA
      {"cert", required_argument, 0, 'c'},
      {"key", required_argument, 0, 'k'},
#elif PLATFORM_SGX
      {"enclave", required_argument, 0, 'e'},
#endif /* PLATFORM OPTIONS */
      {"mode", required_argument, 0, 'm'},
      {"server", required_argument, 0, 's'},
      {"fallback", required_argument, 0, 'b'},
      {"resumption", no_argument, 0, 'r'},
      {0, 0, 0, 0}
    };

#ifdef PLATFORM_VANILA
    const char *opt = "l:d:p:a:n:f:c:k:m:s:b:r0";
#elif PLATFORM_SGX
    const char *opt = "l:d:p:a:n:f:e:m:s:b:r0";
#else
    const char *opt = "l:d:p:a:n:f:m:s:rb:0";
#endif /* PLATFORM_VANILA */

    c = getopt_long(argc, argv, opt, long_options, &option_index);

    if (c == -1)
      break;
    
    switch (c)
    {
      case 'l':
        log_prefix = optarg;
        break;
      case 'd':
        log_directory = optarg;
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'a':
        label = optarg;
        break;
      case 'f':
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
      case 'n':
        msgs = optarg;
        if (access(optarg, F_OK) == -1)
          err |= SEED_ERR_INVALID_MESSAGES_PATH;
        break;
#ifdef PLATFORM_VANILA
      case 'c':
        cert = optarg;
        if (access(optarg, F_OK) == -1)
          err |= SEED_ERR_INVALID_CERT_PATH;
        break;
      case 'k':
        key = optarg;
        if (access(optarg, F_OK) == -1)
          err |= SEED_ERR_INVALID_KEY_PATH;
        break;
#elif PLATFORM_SGX
      case 'e':
        enclave = optarg;
        if (access(optarg, F_OK) == -1)
          err |= SEED_ERR_INVALID_ENCLAVE_PATH;
        break;
#endif /* PLATFORM OPTIONS */
      case 'm':
        tmp = optarg;
        if (strlen(tmp) == 6 && !strncmp(tmp, "vanila", 6))
        {
          mode = EDGE_MODE_VANILA;
          code = "vanila";
        }
        else if (strlen(tmp) == 4 && !strncmp(tmp, "seed", 4))
        {
          mode = EDGE_MODE_SEED;
          code = "seed";
        }
        else if (strlen(tmp) == 2 && !strncmp(tmp, "dc", 2))
        {
          mode = EDGE_MODE_DC;
          code = "dc";
        }
        else if (strlen(tmp) == 7 && !strncmp(tmp, "keyless", 7))
        {
          mode = EDGE_MODE_KEYLESS;
          code = "keyless";
        }
        else if (strlen(tmp) == 5 && !strncmp(tmp, "mbtls", 5))
        {
          mode = EDGE_MODE_MBTLS;
          code = "mbtls";
        }
        else if (strlen(tmp) == 3 && !strncmp(tmp, "spx", 3))
        {
          mode = EDGE_MODE_SPX;
          code = "spx";
        }
        else if (strlen(tmp) == 3 && !strncmp(tmp, "tcp", 3))
        {
          mode = EDGE_MODE_TCP;
          code = "tcp";
        }
        else
          mode = EDGE_MODE_NONE;
        break;
      case 's':
        tmp = optarg;
        if (strlen(tmp) == 6 && !strncmp(tmp, "vanila", 6))
        {
          mode = SERVER_MODE_VANILA;
          code = "vanila";
        }
        else if (strlen(tmp) == 5 && !strncmp(tmp, "mbtls", 5))
        {
          mode = SERVER_MODE_MBTLS;
          code = "mbtls";
        }
        else if (strlen(tmp) == 3 && !strncmp(tmp, "spx", 3))
        {
          mode = SERVER_MODE_SPX;
          code = "spx";
        }
        else
          mode = EDGE_MODE_NONE;
        break;
      case 'b':
        fb_server = optarg;
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
#ifdef PLATFORM_VANILA
    if (err & SEED_ERR_INVALID_CERT_PATH)
    {
      emsg("Invalid cert file path: %s", cert);
    }

    if (err & SEED_ERR_INVALID_KEY_PATH)
    {
      emsg("Invalid key file path: %s", key);
    }
#elif PLATFORM_SGX
    if (err & SEED_ERR_INVALID_ENCLAVE_PATH)
    {
      emsg("Invalid enclave file path: %s", enclave);
    }
#endif /* PLATFORM_SGX */
#ifdef TIME_LOG
    if (err & SEED_ERR_INVALID_MESSAGES_PATH)
    {
      emsg("Invalid message file path: %s", msgs);
    }
#endif /* TIME_LOG */
  }

  if (mode == EDGE_MODE_NONE)
  {
    emsg("You should select the edge mode");
    usage(pname);
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
  imsg("Port: %d", port);
  if (label)
    imsg("Label: %s", label);
#ifdef TIME_LOG
  if (flags < 0)
    flags = SEED_LF_ALL;
  if (!msgs)
    msgs = DEFAULT_NAME_FILE_PATH;
#endif /* TIME_LOG */
  if (flags > 0)
    imsg("Flags: %d", flags);
  if (msgs)
    imsg("Message file: %s", msgs);
#ifdef PLATFORM_VANILA
  imsg("Certificate: %s", cert);
  imsg("Private Key: %s", key);
#elif PLATFORM_SGX
  imsg("Enclave: %s", enclave);
#endif /* PLATFORM */
  imsg("Mode: %s", code);
  imsg("Resumption: %d", resumption);

  initialization();
  arg = init_arg();
#ifdef PLATFORM_VANILA
  arg_set_cert(arg, cert);
  arg_set_key(arg, key);
#elif PLATFORM_SGX
  arg_set_enclave(arg, enclave);
#endif /* PLATFORM ARGUMENTS */
  arg_set_mode(arg, mode);
  arg_set_resumption(arg, resumption);
  ctx = init_edge_ctx(arg);
  free_arg(arg);
	base = event_base_new();
	if (!base) {
		emsg("Could not initialize libevent!");
		return 1;
	}

  info = init_info_ctx(ctx, log_directory, prefix, label, base, 
      msgs, flags, context, mode, code, fb_server);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);

	listener = evconnlistener_new_bind(base, listener_cb, (void *)info,
	    LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_THREADSAFE, 
      -1, (struct sockaddr*)&sin, sizeof(sin));

	if (!listener) {
		emsg("Could not create a listener!");
		return 1;
	}

	signal_event = evsignal_new(base, SIGINT, signal_cb, (void *)info);
  info->base = base;

	if (!signal_event || event_add(signal_event, NULL)<0) {
		emsg("Could not create/add a signal event!");
		return 1;
	}

	event_base_dispatch(base);

	evconnlistener_free(listener);
	event_free(signal_event);
	event_base_free(base);

  free_info_ctx(info);
  free_edge_ctx(ctx);
  free(info);
  free(ctx);
  finalization();

	imsg("done");
	return 0;
}

static void
listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *sa, int socklen, void *user_data)
{
  fstart();
  client_t *client;
  int idx;
	struct bufferevent *bev;
  struct event_base *base;
	info_t *info = (info_t *)user_data;
  
  if (info->mode == SERVER_MODE_VANILA)
  {
    emsg("A client is connected");
  }

  if (evutil_make_socket_nonblocking(fd) < 0)
  {
    emsg("Failed to set the socket to non-blocking");
    abort();
  }
  imsg("Set the socket to non-blocking");

  base = get_event_base(&idx);
  if (!base)
  {
    emsg("No event base is assigned");
    return;
  }

  client = init_client_ctx(info, sa, idx);
  set_time_func(client->logger, UNTRUSTED, get_current_time);
  set_cpu_func(client->logger, UNTRUSTED, get_current_cpu);

	bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	if (!bev) {
		fprintf(stderr, "Error constructing bufferevent!");
		return;
	}
  client->front = bev;
	bufferevent_setcb(bev, conn_readcb, NULL, conn_eventcb, client);
	bufferevent_enable(bev, EV_READ);
  event_base_dispatch(base);

  ffinish();
}

static void
conn_readcb(struct bufferevent *bev, void *user_data)
{
  fstart();
  client_t *client;
  int ret;
  size_t rlen, wlen;
  uint8_t rbuf[BUF_SIZE] = {0, };
  uint8_t wbuf[BUF_SIZE] = {0, };
  struct bufferevent *target;

  client = (client_t *)user_data;

  rlen = bufferevent_read(bev, rbuf, BUF_SIZE);
  if (rlen > 0)
  {
    if (client->fallback)
    {
      ret = fallback_execution(client, rbuf, rlen, wbuf, &wlen);
      target = client->back;
    }
    else if (client->mode == EDGE_MODE_SPX || client->mode == SERVER_MODE_SPX)
    {
      ret = spx_execution(client, rbuf, rlen, wbuf, &wlen);
      if (client->mode == EDGE_MODE_SPX)
        target = client->back;
      else
        target = client->front;
    }
    else
    {
#ifdef TIME_LOG
      if (!client->start)
      {
        client->logger->ops->add(client->logger, SEED_LT_SERVER_BEFORE_TLS_ACCEPT, UNTRUSTED);
        client->start = 1;
      }
      ret = seed_execution(client, rbuf, rlen, wbuf, &wlen);
      target = client->front;
#endif /* TIME_LOG */
    }

    if (ret == SEED_NEED_WRITE)
    {
      assert(wlen > 0);
      bufferevent_write(target, wbuf, wlen);
    }
    else if (ret == SEED_NEED_FALLBACK)
    {
      set_client_fallback(client);
    }
  }
  ffinish();
}

static void
conn_eventcb(struct bufferevent *bev, short events, void *user_data)
{
  fstart();
  client_t *client;
#ifdef TIME_LOG
  logger_t *logger;
#endif /* TIME_LOG */
  client = (client_t *)user_data;
  logger = client->logger;

	if (events & (BEV_EVENT_EOF)) {
		imsg("Connection closed.");
	} else if (events & BEV_EVENT_ERROR) {
		emsg("Got an error on the connection: %s", strerror(errno));
	}
  
  if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR))
  {
#ifdef TIME_LOG
    if (logger->log[SEED_LT_SERVER_AFTER_TLS_ACCEPT].time == 0 
        || logger->log[SEED_LT_SERVER_AFTER_TLS_ACCEPT].cpu == 0)
    {
      logger->ops->add(logger, SEED_LT_SERVER_AFTER_TLS_ACCEPT, UNTRUSTED);
    }
#endif /* TIME_LOG */

    logger->ops->interval(logger, SEED_LT_SERVER_BEFORE_TLS_ACCEPT,
        SEED_LT_SERVER_AFTER_TLS_ACCEPT);

	  bufferevent_free(bev);
    client->front = NULL;
    if (client->back)
      bufferevent_free(client->back);
    free_client_ctx(client);
  }

  ffinish();
}

static void
signal_cb(evutil_socket_t sig, short events, void *user_data)
{
  fstart("sig: %d, events: %d, user_data: %p", sig, events, user_data);
	struct timeval delay = {1, 0};
  info_t *info;
  struct event_base *base;

  info = (info_t *)user_data;
  base = info->base;

	imsg("Caught an interrupt signal; exiting cleanly in one second.");

	event_base_loopexit(base, &delay);

  free_edge_ctx(info->ctx);
  free_info_ctx(info);
  finalization();
  ffinish();
  exit(0);
}
