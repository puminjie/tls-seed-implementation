#include "seed_logger.h"
#include <setting.h>
#include <debug.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>

void
init_names(logger_t *logger, const char *msgs);

logger_t *
init_logger(const char *log_directory, char *log_prefix, 
    const char *msgs, int flags, int context)
{
  fstart("log_directory: %s, log_prefix: %s, msgs: %s, flags: %d, context: %d", log_directory, log_prefix, msgs, flags, context);
  logger_t *ret;
  ret = (logger_t *)malloc(sizeof(logger_t));
  memset(ret, 0x0, sizeof(logger_t));

  ret->log_prefix = (char *)malloc(strlen(log_prefix)+1);
  memset(ret->log_prefix, 0x0, strlen(log_prefix) + 1);
  memcpy(ret->log_prefix, log_prefix, strlen(log_prefix));
  ret->log_directory = log_directory;
  ret->ops = &gops;
  ret->flags = flags;
  ret->context = context;
  init_names(ret, msgs);

  ffinish("ret: %p", ret);
  return ret;
}

void 
init_names(logger_t *logger, const char *msgs)
{
  fstart("logger: %p, msgs: %s", logger, msgs);
  assert(logger != NULL);

  FILE *fp;
  char buf[LBUF_SIZE] = {0};
  char *ptr, *tmp, *name;
  int val, len;

  if (access(msgs, F_OK) == -1)
  {
    emsg("File not exists: %s", msgs);
    abort();
  }

  fp = fopen(msgs, "r");
  
  if (!fp)
    emsg("Cannot open the file: %s", msgs);

  while (feof(fp) == 0)
  {
    memset(buf, 0x0, LBUF_SIZE);
    fgets(buf, LBUF_SIZE, fp);
    ptr = strtok(buf, " ");

    if (!ptr)
      continue;

    if (ptr[0] != '#')
      continue;

    // name
    name = NULL;
    ptr = strtok(NULL, " ");

    if (!ptr)
      continue;

    tmp = strstr(ptr, "SEED");
    if (!tmp)
      continue;

    len = strlen(ptr);
    name = (char *)malloc(len+1);
    memset(name, 0x0, len+1);
    memcpy(name, ptr, len);

    if (!strncmp(name, "__SEED_NAMES_H__", 16))
      continue;

    // value
    ptr = strtok(NULL, " ");
    len = strlen(ptr);
    if (ptr[len-1] == '\n')
      ptr[len-1] = 0;
    val = atoi(ptr);

    logger->name[val] = name;
    dmsg("logger->name[%d] = %s", val, name);
  }

  fclose(fp);

  ffinish();
}

void 
fin_logger(logger_t *logger)
{
  fstart("logger: %p", logger);
  assert(logger != NULL);

  unsigned char log_cpu_file_name[MAX_FILE_NAME_LEN] = {0, };
  unsigned char log_time_file_name[MAX_FILE_NAME_LEN] = {0, };
  int et;
  FILE *cfp, *tfp;
  int i, flags;

  flags = logger->flags;
  et = logger->untrusted_time_func();

  if (flags & SEED_LF_CPU)
  {
    snprintf((char *) log_cpu_file_name, MAX_FILE_NAME_LEN, "%s/%s_cpu_%u.csv",
        logger->log_directory, logger->log_prefix, et);
    cfp = fopen((const char *)log_cpu_file_name, "w");
    for (i=0; i<NUM_OF_LOGS; i++)
    {
      if (logger->log[i].cpu > 0)
      {
        fprintf(cfp, "%d, %s, %lu\n", i, logger->name[i], logger->log[i].cpu);
      }
    }
    fclose(cfp);
  }

  if (flags & SEED_LF_TIME)
  {
    snprintf((char *) log_time_file_name, MAX_FILE_NAME_LEN, "%s/%s_time_%u.csv",
        logger->log_directory, logger->log_prefix, et);
    tfp = fopen((const char *)log_time_file_name, "w");
    for (i=0; i<NUM_OF_LOGS; i++)
    {
      if (logger->log[i].time > 0)
      {
        fprintf(tfp, "%d, %s, %lu\n", i, logger->name[i], logger->log[i].time);
      }
    }
    fclose(tfp);
  }

  if (logger->log_prefix)
  {
    free(logger->log_prefix);
    logger->log_prefix = NULL;
  }

  if (logger->name)
  {
    for (i=0; i < NUM_OF_LOGS; i++)
    {
      if (logger->name[i])
      {
        free(logger->name[i]);
        logger->name[i] = NULL;
      }
    }
  }

  free(logger);
  ffinish();
}

void
set_time_func(logger_t *logger, int region, unsigned long (*time_func)(void))
{
  fstart("logger: %p, region: %d, time_func: %p", logger, region, time_func);
  if (region == TRUSTED)
    logger->trusted_time_func = time_func;
  else
    logger->untrusted_time_func = time_func;
  ffinish();
}

void
set_cpu_func(logger_t *logger, int region, unsigned long (*cpu_func)(void))
{
  fstart("logger: %p, region: %d, cpu_func: %p", logger, region, cpu_func);
  if (region == TRUSTED)
    logger->trusted_cpu_func = cpu_func;
  else
    logger->untrusted_cpu_func = cpu_func;
  ffinish();
}

int 
seed_add(logger_t *logger, int name, int region)
{
  fstart("logger: %p, name: %s, region: %d", logger, logger->name[name], region);
  assert(logger != NULL);
  assert(name >= 0);
  
  int flags;
  int context;

  flags = logger->flags;
  context = logger->context;

  if (region == LIBRARY)
  {
    if (context == SEED_UNTRUSTED_LIBRARY)
      region = UNTRUSTED;
    else
      region = TRUSTED;
  }

  if (flags & SEED_LF_CPU)
  {
    if (region == TRUSTED)
    {
      if (logger->trusted_cpu_func)
        logger->log[name].cpu = logger->trusted_cpu_func();
    }
    else
    {
      if (logger->untrusted_cpu_func)
        logger->log[name].cpu = logger->untrusted_cpu_func();
    }
  }

  if (flags & SEED_LF_TIME)
  {
    if (region == TRUSTED)
    {
      if (logger->trusted_time_func)
        logger->log[name].time = logger->trusted_time_func();
    }
    else
    {
      if (logger->untrusted_time_func)
        logger->log[name].time = logger->untrusted_time_func();
    }
  }

  ffinish();
  return SUCCESS;
}

int
seed_move(logger_t *logger, int from, int to)
{
  fstart("logger: %p, from: %s, to: %s", logger, logger->name[from], logger->name[to]);

  logger->log[to].cpu = logger->log[from].cpu;
  logger->log[to].time = logger->log[from].time;

  ffinish();
  return SUCCESS;
}

int 
seed_interval(logger_t *logger, int start, int end)
{
  fstart("logger: %p, start: %s, end: %s", logger, logger->name[start], logger->name[end]);
  assert(logger != NULL);
  assert(start >= 0);
  assert(end > start);

  int flags;

  const char *nstart;
  const char *nend;

  unsigned long cstart;
  unsigned long cend;
  unsigned long tstart;
  unsigned long tend;

  flags = logger->flags;

  nstart = logger->name[start];
  nend = logger->name[end];

  cstart = logger->log[start].cpu;
  cend = logger->log[end].cpu;
  tstart = logger->log[start].time;
  tend = logger->log[end].time;

  if (flags & SEED_LF_CPU)
  {
    printf("cpu) from %s to %s: %lu ms\n", nstart, nend, cend - cstart); 
  }

  if (flags & SEED_LF_TIME)
  {
    printf("time) from %s to %s: %lu ms\n", nstart, nend, tend - tstart);
  }

  ffinish();
  return SUCCESS;
}

int
seed_print(logger_t *logger, int name, int flags)
{
  fstart("logger: %p, name: %s", logger, logger->name[name]);
  assert(logger != NULL);
  assert(name >= 0);
  assert(flags >= 0);
  
  if (flags & SEED_LF_CPU)
  {
    imsg("cpu) at %s: %lu ms", logger->name[name], logger->log[name].cpu);
  }

  if (flags & SEED_LF_TIME)
  {
    imsg("time) at %s: %lu ms", logger->name[name], logger->log[name].time);
  }

  ffinish();
  return SUCCESS;
}

int 
seed_print_all(logger_t *logger)
{
  fstart("logger: %p", logger);
  assert(logger != NULL);

  int i, flags;
  flags = logger->flags;

  if (flags & SEED_LF_CPU)
  {
    for (i=0; i<NUM_OF_LOGS; i++)
    {
      if (logger->log[i].cpu > 0)
      {
        seed_print(logger, i, SEED_LF_CPU);
      }
    }
  }

  if (flags & SEED_LF_TIME)
  {
    for (i=0; i<NUM_OF_LOGS; i++)
    {
      if (logger->log[i].time > 0)
      {
        seed_print(logger, i, SEED_LF_TIME);
      }
    }
  }

  ffinish();
  return SUCCESS;
}
