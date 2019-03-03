#ifndef __TCP_HEADER_H__
#define __TCP_HEADER_H__

#include <linux/types.h>
#include <linux/tcp.h>

struct pseudohdr
{
  uint32_t ip_src;
  uint32_t ip_dst;
  uint8_t zero;
  uint8_t protocol;
  uint16_t tcp_len;
  struct tcphdr tcph;
};

#endif /* __TCP_HEADER_H__ */
