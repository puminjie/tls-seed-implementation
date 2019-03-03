#include "rdns.h"
#include "edge_log.h"

void init_table(void)
{
  INIT_LIST_HEAD(&head.list);
  EDGE_LOG("init_table");
}

void free_table(void)
{
  struct list_head *p;
  struct info *walk;

  EDGE_LOG("free_table");
  // Stop the kernel thread

  list_for_each(p, &head.list)
  {
    walk = list_entry(p, struct info, list);
    list_del(p);
    kfree(walk);
  }
}

struct info *get_by_ip(uint32_t addr)
{
  struct list_head *p;
  struct info *ret = NULL;
  struct info *walk;
  EDGE_LOG("get_by_ip");

  list_for_each(p, &head.list)
  {
    walk = list_entry(p, struct info, list);
    if (walk->ip == addr)
    {
      EDGE_LOGip("Search for", addr);
      EDGE_LOGip("Found in struct", walk->ip);
      ret->ref++;
      ret = walk;
      break;
    }
  }

  return ret;
}

struct info *get_by_name(uint8_t *n, uint32_t len)
{
  struct list_head *p;
  struct info *ret = NULL;
  struct info *walk;
  EDGE_LOG("get_by_name");

  list_for_each(p, &head.list)
  {
    walk = list_entry(p, struct info, list);
    if (walk->nlen == len)
    {
      if (!strncmp(walk->name, n, walk->nlen))
      {
        EDGE_LOG2s("Query", n, len);
        EDGE_LOG2s("Found", walk->name, walk->nlen);
        ret->ref++;
        ret = walk;
        break;
      }
    }
  }

  return ret;
}

struct info *insert_entry(uint32_t addr, uint8_t *n, uint32_t len)
{
  struct info *ret;
  struct timeval t;
  EDGE_LOG("insert_entry");
  
  ret = get_by_name(n, len);

  if (!ret || (ret->ip != addr))
  {
    EDGE_LOG("New entry");
    ret = (struct info *)kmalloc(sizeof(struct info), GFP_KERNEL);
    ret->ip = addr;
    memcpy(ret->name, n, len);
    ret->nlen = len;
    do_gettimeofday(&t);
    ret->ts = TIMEVAL_TO_TS(&t);
    ret->ref = 0;

    list_add(&ret->list, &head.list);
  }
  else
    EDGE_LOG("The entry is existed");

  return ret;
}
