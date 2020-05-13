#ifndef __LOGGER_H__
#define __LOGGER_H__

#include "defines.h"
#include "logs.h"
#include <time.h>

typedef struct logger_ops_st logger_ops;

typedef struct logger_st
{
  const char *log_directory;
  char *log_prefix;
  log_t log[NUM_OF_LOGS];
  char *name[NUM_OF_LOGS];
  int flags;
  int context;
  unsigned long (*untrusted_time_func)(void);
  unsigned long (*untrusted_cpu_func)(void);
  unsigned long (*trusted_time_func)(void);
  unsigned long (*trusted_cpu_func)(void);
  logger_ops *ops;
} logger_t;

typedef struct logger_ops_st
{
  int (*add)(logger_t *logger, int name, int region);
  int (*move)(logger_t *logger, int from, int to);
  int (*interval)(logger_t *logger, int start, int end);
  int (*print)(logger_t *logger, int name, int flags);
  int (*print_all)(logger_t *logger);
} logger_ops_t;


logger_t *init_logger(const char *log_directory, char *log_prefix, 
    const char *msgs, int flags, int region);
void fin_logger(logger_t *logger);

void set_time_func(logger_t *logger, int region, unsigned long (*time_func)(void));
void set_cpu_func(logger_t *logger, int region, unsigned long (*cpu_func)(void));

#endif /* __LOGGER_H__ */
