#ifndef __RDNS_H__
#define __RDNS_H__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>

#define MAX_RECORDS       1024
#define MAX_NAME_LENGTH   255
#define MAX_TTL_VALUE     30
#define MAX_INFO_VALUE    10

#define KHZ               1000
#define TIME_TICK         (1000000 / KHZ)
#define TIMEVAL_TO_TS(t)  (uint32_t)((t)->tv_sec * KHZ + ((t)->tv_usec / TIME_TICK))

struct info {
  uint32_t ip;
  uint8_t name[MAX_NAME_LENGTH];
  uint8_t nlen;
  uint8_t ref;
  uint32_t ts;

  struct list_head list;
};

extern struct info head;

void init_table(void);
void free_table(void);
struct info *get_by_ip(uint32_t addr);
struct info *get_by_name(uint8_t *n, uint32_t len);
struct info *insert_entry(uint32_t addr, uint8_t *n, uint32_t len);

#endif /* __RDNS_H__ */
