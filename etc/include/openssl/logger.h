#ifndef __LOGGER_H__
#define __LOGGER_H__

#include <openssl/defines.h>
#include <openssl/logs.h>

typedef struct logger_ops_st logger_ops;

typedef struct logger_st
{
  const char *log_prefix;
  log_t log[NUM_OF_LOGS];
  char *name[NUM_OF_LOGS];
  int flags;
  unsigned long (*untrusted_time_func)(void);
  unsigned long (*trusted_time_func)(void);
  logger_ops *ops;
} logger_t;

typedef struct logger_ops_st
{
  int (*add)(logger_t *logger, int name, int region);
  int (*interval)(logger_t *logger, int start, int end);
  int (*print)(logger_t *logger, int name, int flags);
  int (*print_all)(logger_t *logger);
} logger_ops_t;


logger_t *init_logger(const char *log_prefix, int flags);
void fin_logger(logger_t *logger);

void set_time_func(logger_t *logger, int region, unsigned long (*time_func)(void));

#ifdef TIME_LOG
#define DECLARE_LOGGER(s) \
  logger_t *logger; 
#define RECORD_LOG(s, name, region) \
  logger = SSL_get_time_logger(s); \
  logger->add(logger, name, region); 
#define INTERVAL(s, start, end) \
  logger = SSL_get_time_logger(s); \
  logger->interval(logger, start, end);
#else
#define DECLARE_LOGGER(s)
#define RECORD_LOG(s, name, region)
#define INTERVAL(s, start, end)
#endif /* TIME_LOG */

#endif /* __LOGGER_H__ */
