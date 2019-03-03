/** 
 * @file logs.h
 * @author Hyunwoo Lee
 * @date 21 Feb 2018
 * @brief This file is to define log messages
 */

#ifndef __LOG_CLIENT_H__
#define __LOG_CLIENT_H__

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <sys/time.h>
#include <assert.h>
#include <errno.h>
#include <openssl/logs.h>

#ifdef TIME_LOG
#include "sys_timer.h"
#endif /* TIME_LOG */

#ifdef DEBUG
int log_idx;
unsigned char ipb[4];
#define EDGE_LOGip(msg, ip) \
  ipb[0] = ip & 0xFF; \
  ipb[1] = (ip >> 8) & 0xFF; \
  ipb[2] = (ip >> 16) & 0xFF; \
  ipb[3] = (ip >> 24) & 0xFF; \
  fprintf(stderr, "[edge] %s:%s:%d %s: %d.%d.%d.%d\n", \
      __FILE__, __func__, __LINE__, msg, ipb[0], ipb[1], ipb[2], ipb[3]);
#define EDGE_LOGmac(msg, mac) \
  fprintf(stderr, "[edge] %s:%s:%d %s: %x %x %x %x %x %x\n", \
      __FILE__, __func__, __LINE__, msg, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
#define EDGE_LOGinfo(ip, port) \
  ipb[0] = ip & 0xFF; \
  ipb[1] = (ip >> 8) & 0xFF; \
  ipb[2] = (ip >> 16) & 0xFF; \
  ipb[3] = (ip >> 24) & 0xFF; \
  fprintf(stderr, "[edge] %s:%s:%d: A client is accepted from %d.%d.%d.%d:%d\n", \
      __FILE__, __func__, __LINE__, ipb[0], ipb[1], ipb[2], ipb[3], ntohs(port));
#else
#define EDGE_LOGip(msg, ip)
#define EDGE_LOGmac(msg, mac)
#define EDGE_LOGinfo(ip, port)
#endif /* DEBUG */

#ifdef TIME_LOG
int lidx;
FILE *log_file;

#define INITIALIZE_LOG(arr) \
  for (lidx=0; lidx<NUM_OF_LOGS; lidx++) \
    arr[lidx].time = 0; \

#define PRINT_LOG(arr) ({ \
  for ((lidx)=0; (lidx) < (NUM_OF_LOGS); (lidx)++) \
    if (arr[lidx].time > 0) \
      printf("%s: %lu\n", arr[lidx].name, arr[lidx].time); \
  })

/*
#define RECORD_LOGu(arr, n) \
  if (arr) { \
    memcpy(arr[n].name, #n, sizeof(#n)); \
    arr[n].time = get_cntvct(); \
  }
*/

#define RECORD_LOGu(arr, n) \
  if (arr) { \
    arr[n].time = get_cntvct(); \
  }

/*
#define FINALIZE(arr, fname) \
  log_file = fopen(fname, "w"); \
  for (lidx = 0; lidx < NUM_OF_LOGS; lidx++) \
  { \
    if (arr[lidx].time > 0) \
      fprintf(log_file, "%lu, %d, %s\n", arr[lidx].time, lidx, arr[lidx].name); \
  } \
  fclose(log_file);
*/

#define FINALIZE(arr, fname) \
  log_file = fopen(fname, "w"); \
  for (lidx = 0; lidx < NUM_OF_LOGS; lidx++) \
  { \
    if (arr[lidx].time > 0) \
      fprintf(log_file, "%lu, %d\n", arr[lidx].time, lidx); \
  } \
  fclose(log_file);

#else
#define INITIALIZE_LOG(arr)
#define PRINT_LOG(arr)
#define RECORD_LOGu(arr, n)
#define FINALIZE(arr, fname)
#endif /* TIME_LOG */

#endif /* __LOG_CLIENT_H__ */
