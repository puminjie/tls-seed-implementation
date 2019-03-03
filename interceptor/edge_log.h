#ifndef __EDGE_LOG_H__
#define __EDGE_LOG_H__

#include <linux/time.h>
#include <linux/types.h>

#ifdef DEBUG
#define EDGE_LOG(msg) \
  printk(KERN_DEBUG "[edge] %s:%s:%d: %s\n", __FILE__, __func__, __LINE__, msg);

#define EDGE_LOG1d(msg, arg1) \
  printk(KERN_DEBUG "[edge] %s:%s:%d: %s:%d\n", __FILE__, __func__, __LINE__, msg, arg1);

#define EDGE_LOG1u(msg, arg1) \
  printk(KERN_DEBUG "[edge] %s:%s:%d: %s:%u\n", __FILE__, __func__, __LINE__, msg, arg1);

#define EDGE_LOG1x(msg, arg1) \
  printk(KERN_DEBUG "[edge] %s:%s:%d: %s:%x\n", __FILE__, __func__, __LINE__, msg, arg1);

#define EDGE_LOG1s(msg, arg1) \
  printk(KERN_DEBUG "[edge] %s:%s:%d: %s:%s\n", __FILE__, __func__, __LINE__, msg, arg1);

#define EDGE_LOG2s(msg, arg1, arg2) \
  arg1[arg2] = '\0'; \
  printk(KERN_DEBUG "[edge] %s:%s:%d: %s:%s\n", __FILE__, __func__, __LINE__, msg, arg1);

#define EDGE_LOGip(msg, ip) \
  printk(KERN_DEBUG "[edge] %s:%s:%d: %s: %d.%d.%d.%d\n", __FILE__, __func__, __LINE__, msg, (ip & 0xff), ((ip >> 8) & 0xff), ((ip >> 16) & 0xff), ((ip >> 24) & 0xff));

#define EDGE_LOGinfo(msg, ip, port) \
  printk(KERN_DEBUG "[edge] %s:%s:%d: %s: %d.%d.%d.%d:%d\n", __FILE__, __func__, __LINE__, msg, (ip & 0xff), ((ip >> 8) & 0xff), ((ip >> 16) & 0xff), ((ip >> 24) & 0xff), ntohs(port));

#define EDGE_LOGts(msg, ts) \
  printk(KERN_DEBUG "[edge] %u\n", ts);
#else
#define EDGE_LOG(msg)
#define EDGE_LOG1d(msg, arg1)
#define EDGE_LOG1u(msg, arg1)
#define EDGE_LOG1x(msg, arg1)
#define EDGE_LOG1s(msg, arg1)
#define EDGE_LOG2s(msg, arg1, arg2)
#define EDGE_LOGip(msg, ip)
#define EDGE_LOGinfo(msg, ip, port)
#endif /* DEBUG */

#endif /* __EDGE_LOG_H__ */
