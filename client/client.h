#ifndef __CLIENT_H__
#define __CLIENT_H__

#define DEFAULT_HOST_NAME         "www.bob.com"
#define DEFAULT_LOG_DIRECTORY     "log"
#define DEFAULT_LOG_NAME_FILE     "../src/logger/seed_names.h"
#define DEFAULT_PORT_NUMBER       5555
#define DEFAULT_NUM_OF_THREADS    1
#define DEFAULT_LOG_PREFIX        "log"

#define CLIENT_MODE_NONE          0
#define CLIENT_MODE_VANILA        1
#define CLIENT_MODE_SEED          2
#define CLIENT_MODE_DC            3
#define CLIENT_MODE_KEYLESS       4
#define CLIENT_MODE_MBTLS         5
#define CLIENT_MODE_SPX           6
#define CLIENT_MODE_TCP           7

#define ERR_CLIENT_MODE_NONE      1
#define ERR_INVALID_MESSAGES_PATH 2

#define BUF_SIZE 16384
#define MAX_PATH_LEN 256

#define DELIMITER "\r\n"
#define DELIMITER_LEN 2

typedef struct arg_st
{
  const char *host;
  int port;
  const char *content;
  int mode;
  int idx;
  const char *code;
  const char *msgs;
  const char *name;
  int flags;
  int resumption;

  SSL_CTX *ctx;

  const char *log_directory;
  char *log_prefix;
} arg_t;

#endif /* __CLIENT_H__ */
