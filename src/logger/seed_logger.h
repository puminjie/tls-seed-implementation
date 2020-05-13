#ifndef __SEED_LOGGER_H__
#define __SEED_LOGGER_H__

#include <openssl/logger.h>
#include "seed_names.h"
#include "seed_flags.h"

int seed_add(logger_t *logger, int name, int region);
int seed_move(logger_t *logger, int from, int to);
int seed_interval(logger_t *logger, int start, int end);
int seed_print(logger_t *logger, int name, int flags);
int seed_print_all(logger_t *logger);

static logger_ops_t gops = 
{
  .add = seed_add,
  .move = seed_move,
  .interval = seed_interval,
  .print = seed_print,
  .print_all = seed_print_all,
};

#endif /* __SEED_LOGGER_H__ */
