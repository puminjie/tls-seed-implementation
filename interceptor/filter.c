#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netlink.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/skbuff.h>
#include <net/sock.h>

#include "rdns.h"
#include "edge_log.h"
#include "tcp_header.h"
#include "checksum.h"
//#include "sys_timer.h"

#define NETLINK_USER 31
#define INVALID 0

#define EXP_ADDR "147.46.216.213"
#define KOR_ADDR "54.180.80.240"
#define USA_ADDR "18.204.198.218"
#define JPN_ADDR "18.182.10.209"
#define SERV_ADDR "54.180.80.8"
#define EC_ADDR   "192.168.8.1"
#define CLNT_ADDR "192.168.8.136"

#define EPORT 5552
#define KPORT 5553
#define JPORT 5554
#define UPORT 5555

static struct nf_hook_ops send, recv;
static int pid = 0;
struct info head = {
  .ip = 0,
  .nlen = 0,
  .ref = 0,
  .ts = 0,
};
struct sock *nl_sk = NULL;
struct iphdr *iph;
struct tcphdr *tcph;
struct udphdr *udph;
struct nlmsghdr *nlh;
struct sk_buff *pkt;
struct sk_buff *out;
char *data;
int data_len, ret;
__be32 ec, serv, clnt;
__be32 experiment, usa, jpn, kor;

struct dnsmsg
{
  uint16_t trans_id;
  uint16_t flags;
  uint16_t questions;
  uint16_t answer;
  uint16_t authority;
  uint16_t additional;
};

__be32 ipv4_to_ul(const char *ip);
void parse_dns_query_info(unsigned char *p);
void parse_dns_response_info(unsigned char *p);
//static __be16 ip_fast_csum(const void *iph, unsigned int ihl);
//static __be16 tcp_calc_checksum(struct iphdr *iph, struct tcphdr *tcph, __be16 len);

static void nl_recv_msg(struct sk_buff *skb)
{
  //printk(KERN_DEBUG "Entering: %s\n", __FUNCTION__);
  nlh = (struct nlmsghdr *)skb->data;
  //printk(KERN_DEBUG "Netlink received msg payload: %s\n", (char *)nlmsg_data(nlh));
  pid = nlh->nlmsg_pid;
  //printk(KERN_DEBUG "Sending PID: %d\n", pid);
}

unsigned int sending_hook(void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state)
{
  __u16 sport;

  pkt = skb;

  if (!skb)
  {
    return NF_ACCEPT;
  }

  iph = (struct iphdr *)skb_network_header(pkt);

  if (!iph)
  {
    return NF_ACCEPT;
  }

  if (iph->protocol == IPPROTO_TCP)
  {
    tcph = (struct tcphdr *)skb_transport_header(pkt);

    if (iph->saddr == ec && iph->daddr == clnt)
    {
      sport = ntohs(tcph->source);

      if (sport == EPORT)
        iph->saddr = experiment;
      else if (sport == KPORT)
        iph->saddr = kor;
      else if (sport == JPORT)
        iph->saddr = jpn;
      else if (sport == UPORT)
        iph->saddr = usa;

      update_checksum(pkt);
    }
  }

  return NF_ACCEPT;
}

unsigned int receiving_hook(void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state)
{
  unsigned char *p;
  __u16 dport;

  pkt = skb;

  if (!skb)
  {
    return NF_ACCEPT;
  }

  iph = (struct iphdr *)skb_network_header(pkt);

  if (!iph)
  {
    return NF_ACCEPT;
  }

  if (iph->protocol == IPPROTO_TCP)
  {
    tcph = (struct tcphdr *)skb_transport_header(pkt);
    dport = ntohs(tcph->dest);

    if ((iph->saddr == clnt) && 
        ((iph->daddr == experiment && dport == EPORT) ||
         (iph->daddr == kor && dport == KPORT) ||
         (iph->daddr == jpn && dport == JPORT) ||
         (iph->daddr == usa && dport == UPORT)))
    {
        iph->daddr = ec;
        update_checksum(pkt);
    }
  }

  if (iph->protocol == IPPROTO_UDP)
  {
    udph = (struct udphdr *)skb_transport_header(pkt);
    data_len = ntohs(udph->len) - 8;

    if (ntohs(udph->dest) == 53)
    {
      //EDGE_LOG("This is a DNS query");
      //EDGE_LOGinfo("  UDP Source", iph->saddr, udph->source);
      //EDGE_LOGinfo("  UDP Destination", iph->daddr, udph->dest);
      //printk(KERN_DEBUG "  UDP Data Length: %u\n", data_len);

      if (data_len > 0)
      {
        p = (unsigned char *)udph + 8;
        parse_dns_query_info(p);
      }
    }

    if (ntohs(udph->source) == 53)
    {
      //EDGE_LOG("This is a DNS reply");
      //EDGE_LOGinfo("  UDP Source", iph->saddr, udph->source);
      //EDGE_LOGinfo("  UDP Destination", iph->daddr, udph->dest);
      //printk(KERN_DEBUG "  UDP Data Length: %u\n", data_len);

      if (data_len > 0)
      {
        p = (unsigned char *)udph + 8;
        parse_dns_response_info(p);
      }
    }
  }

  return NF_ACCEPT;
}

__be32 ipv4_to_ul(const char *ip)
{
  __be32 ret;
  int i;
  const char *start;

  start = ip;
  ret = 0;

  for (i=0; i<4; i++)
  {
    char c;
    int n = 0;
    while (1)
    {
      c = *start;
      start++;

      if (c >= '0' && c <= '9')
      {
        n *= 10;
        n += c - '0';
      }
      else if ((i < 3 && c == '.') || i == 3)
      {
        break;
      }
      else
      {
        return INVALID;
      }
    }

    if (n >= 256)
      return INVALID;

    ret <<= 8;
    ret |= n;
  }

  return htonl(ret);
}

void parse_dns_query_info(unsigned char *p)
{
  struct nlmsghdr *nlh = NULL;
  struct dnsmsg *dnsinfo;
  struct sk_buff *skb_out;
  unsigned char domain[256] = {0, };
  int offset = 0, questions, ret, n;
  unsigned char num;

  dnsinfo = (struct dnsmsg *)p;
  p = (unsigned char *)(dnsinfo + 1);

  //printk(KERN_DEBUG "DNS Query Info.");
  //printk(KERN_DEBUG "  Transaction ID: 0x%04x\n", ntohs(dnsinfo->trans_id));
  //printk(KERN_DEBUG "  Flags: %04x\n", ntohs(dnsinfo->flags));
  //printk(KERN_DEBUG "  Questions: %d\n", ntohs(dnsinfo->questions));
  //printk(KERN_DEBUG "  Answer: %d\n", ntohs(dnsinfo->answer));
  //printk(KERN_DEBUG "  Authority: %d\n", ntohs(dnsinfo->authority));
  //printk(KERN_DEBUG "  Additional: %d\n", ntohs(dnsinfo->additional));

  n = questions = ntohs(dnsinfo->questions);

  while (questions > 0)
  {
    num = *(p++);
    do {
      memcpy(domain + offset, p, num);
      p += num;
      offset += num;
      domain[offset] = '.';
      offset += 1;
      num = *(p++);
    } while (num > 0);

    domain[offset-1] = 0;
    questions--;
    //printk(KERN_DEBUG "  Query Domain: %s\n", domain);
    skb_out = nlmsg_new(offset, 0);
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, offset, 0);
    NETLINK_CB(skb_out).dst_group = 0;
    strncpy(nlmsg_data(nlh), domain, offset);

    ret = nlmsg_unicast(nl_sk, skb_out, pid);

    if (ret < 0)
      //printk(KERN_DEBUG "Error while sending the domain name to the user\n");

    p += 4;
    memset(domain, 0, 256);
  }
}

void parse_dns_response_info(unsigned char *p)
{
  struct dnsmsg *dnsinfo;
  //struct info *info;
  unsigned char domain[256] = {0, };
  int offset = 0, questions, answer;
  unsigned char num;
  uint16_t length;
  uint32_t addr;

  dnsinfo = (struct dnsmsg *)p;
  p = (unsigned char *)(dnsinfo + 1);

  //printk(KERN_DEBUG "DNS Response Info.");
  //printk(KERN_DEBUG "  Transaction ID: 0x%04x\n", ntohs(dnsinfo->trans_id));
  //printk(KERN_DEBUG "  Flags: %04x\n", ntohs(dnsinfo->flags));
  //printk(KERN_DEBUG "  Questions: %d\n", ntohs(dnsinfo->questions));
  //printk(KERN_DEBUG "  Answer: %d\n", ntohs(dnsinfo->answer));
  //printk(KERN_DEBUG "  Authority: %d\n", ntohs(dnsinfo->authority));
  //printk(KERN_DEBUG "  Additional: %d\n", ntohs(dnsinfo->additional));
  questions = ntohs(dnsinfo->questions);
  answer = ntohs(dnsinfo->answer);

  while (questions > 0)
  {
    num = *(p++);
    do {
      memcpy(domain + offset, p, num);
      p += num;
      offset += num;
      domain[offset] = '.';
      offset += 1;
      num = *(p++);
    } while (num > 0);

    domain[offset-1] = '\0';
    questions--;
    //printk(KERN_DEBUG "  Query Domain: %s\n", domain);
    p += 4;
    memset(domain, 0, 256);
  }

  while (answer > 0)
  {
    p += 10;
    length = *(p++) & 0xff << 8;
    length |= *(p++) & 0xff;
    //printk(KERN_DEBUG "  Data Length: %d\n", length);
    addr = *((uint32_t *)p);
    //EDGE_LOGip("  DNS Answer", addr);
    answer--;
//    info = insert_entry(addr, "www.google.com", 14);

//    EDGE_LOGip("IP address in the entry", info->ip);
//    EDGE_LOG2s("Name in the entry", info->name, info->nlen);
//    EDGE_LOGts("Timestamp in the entry", info->ts);
  }
}

/*
static __u16 tcp_calc_checksum(struct iphdr *iph, struct tcphdr *tcph, __u16 len)
{
  __u32 sum;
  __u16 *w;
  w = (__u16 *)tcph;

  sum = 0;

  sum += (iph->saddr >> 16) & 0xffff;
  sum += (iph->saddr) & 0xffff;
  sum += (iph->daddr >> 16) & 0xffff;
  sum += (iph->daddr) & 0xffff;
  sum += htons(IPPROTO_TCP);
  sum += htons(len);

  while (len > 1)
  {
    sum += *w++;
    len -= 2;
  }

  if (len)
    sum += (*w & htons(0xff00));

  while (sum >> 16)
  {
    sum = (sum >> 16) + (sum & 0xFFFF);
  }

  sum = ~sum;

  return (__u16)sum;
}
*/

static int __init initialize(void)
{
  struct netlink_kernel_cfg cfg = {
    .input = nl_recv_msg,
  };

  send.hook     = sending_hook;
  //send.hooknum  = NF_INET_LOCAL_OUT;
  send.hooknum  = NF_INET_POST_ROUTING;
  send.pf       = PF_INET;
  send.priority = NF_IP_PRI_LAST;

  recv.hook     = receiving_hook;
  recv.hooknum  = NF_INET_PRE_ROUTING;
  recv.pf       = PF_INET;
  recv.priority = NF_IP_PRI_LAST;

  //printk(KERN_DEBUG "Entering: %s\n", __FUNCTION__);

  nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);

  if (!nl_sk)
  {
    //printk(KERN_ALERT "Error creating socket\n");
    return -10;
  }

  nf_register_net_hook(&init_net, &send);
  nf_register_net_hook(&init_net, &recv);
  //printk(KERN_DEBUG "Register Netfilter Hook\n");

  ec = ipv4_to_ul(EC_ADDR);
  experiment = ipv4_to_ul(EXP_ADDR);
  usa = ipv4_to_ul(USA_ADDR);
  jpn = ipv4_to_ul(JPN_ADDR);
  kor = ipv4_to_ul(KOR_ADDR);
  serv = ipv4_to_ul(SERV_ADDR);
  clnt = ipv4_to_ul(CLNT_ADDR);
  EDGE_LOGip("EC IP", ec);
  EDGE_LOG1x("EC ul", ec);
  EDGE_LOGip("Server IP", serv);
  EDGE_LOG1x("Server ul", serv);
  EDGE_LOGip("Client IP", clnt);
  EDGE_LOG1x("Client ul", clnt);

  //nf_register_hook(&nfho); for the lower version of the kernel.

  init_table();

  return 0;
}

static void __exit cleanup(void)
{
  nf_unregister_net_hook(&init_net, &send);
  nf_unregister_net_hook(&init_net, &recv);
  //printk(KERN_DEBUG "Unregister Netfilter Hook\n");
  netlink_kernel_release(nl_sk);
  //printk(KERN_DEBUG "Release Netlink Kernel Socket\n");
  //nf_unregister_hook(&nfho); for the lower version of the kernel.

  free_table();
}

module_init(initialize);
module_exit(cleanup);
