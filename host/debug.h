#ifndef __CMD_STR_H__
#define __CMD_STR_H__

#define MAX_COMMANDS 256
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

#include <ta_edge_cache.h>

static char *commands[MAX_COMMANDS]; 

void init_commands(void);
char *cmd_to_str(int num);

#endif /* __CMD_STD_H__ */
