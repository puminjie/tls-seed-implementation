#ifndef __SDEBUG_H__
#define __SDEBUG_H__

#include <stdio.h>
#include <assert.h>

#define DEBUG_LEVEL 0
#define ONE_LINE 16

#define LFINFO 0
#define LDEBUG 1
#define LINFO 2
#define LERROR 3

static int count_idx;

#if DEBUG_LEVEL <= LFINFO
#define sstart(format, ...) printf("[SEED/FINFO] Start: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
#define sfinish(format, ...) printf("[SEED/FINFO] Finish: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
#define serr(format, ...) printf("[SEED/FINFO] Error: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
#else
#define sstart(format, ...)
#define sfinish(format, ...)
#define serr(format, ...)
#endif /* LFINFO */

#if DEBUG_LEVEL <= LDEBUG
#define sdmsg(format, ...) printf("[SEED/DEBUG] %s:%s:%d: " format "\n", __FILE__, __func__, __LINE__, ## __VA_ARGS__)
#define sdprint(msg, buf, start, end, interval) \
  printf("[SEED/DEBUG] %s:%s: %s (%d bytes)\n", __FILE__, __func__, msg, end - start); \
  for (count_idx = start; count_idx < end; count_idx++) \
  { \
    printf("%02X ", buf[count_idx]); \
    if (count_idx % interval == (interval - 1)) \
    { \
      printf("\n"); \
    } \
  } \
  printf("\n");
#else
#define sdmsg(format, ...)
#define sdprint(msg, buf, start, end, interval)
#endif /* DEBUG */

#if DEBUG_LEVEL <= LINFO
#define simsg(format, ...) printf("[SEED/INFO] %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
#define siprint(msg, buf, start, end, interval) \
  printf("[SEED/INFO] %s:%s: %s (%d bytes)\n", __FILE__, __func__, msg, end - start); \
  for (count_idx = start; count_idx < end; count_idx++) \
  { \
    printf("%02X ", buf[count_idx]); \
    if (count_idx % interval == (interval - 1)) \
    { \
      printf("\n"); \
    } \
  } \
  printf("\n");
#else
#define simsg(format, ...)
#define siprint(msg, buf, start, end, interval)
#endif /* INFO */

#if DEBUG_LEVEL <= LERROR
#define semsg(format, ...) printf("[SEED/ERROR] " format "\n", ## __VA_ARGS__)
#else
#define semsg(format, ...)
#endif /* ERROR */

#endif /* __SDEBUG_H__ */
