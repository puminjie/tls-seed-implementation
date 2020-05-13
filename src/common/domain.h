#ifndef __DOMAIN_H__
#define __DOMAIN_H__

#include <stdint.h>

#ifndef SUCCESS
#define SUCCESS 1
#endif /* SUCCESS */

#ifndef FAILURE
#define FAILURE 0
#endif /* FAILURE */

#ifndef TRUE
#define TRUE 1
#endif /* TRUE */

#ifndef FALSE
#define FALSE 0
#endif /* FALSE */

typedef struct domain_st 
{
  uint8_t *domain;
  int dlen;

  uint8_t *cert;
  int clen;

  uint8_t *cc;
  uint16_t ht;
  int cclen;

  struct domain_st *next;
} domain_t;

typedef struct domain_list_st
{
  int num;
  domain_t *head;
} domain_list_t;

domain_list_t *init_domain_list(void);
void free_domain_list(domain_list_t *list);
void print_domain_list(domain_list_t *list);

domain_t *init_domain(void);
void free_domain(domain_t *dom);

domain_t *find_domain(domain_list_t *list, uint8_t *domain, int dlen);
int add_domain_cert(domain_list_t *list, uint8_t *domain, int dlen, uint8_t *cert, int clen);
int add_domain_cc(domain_list_t *list, uint8_t *domain, int dlen, uint8_t *cc, uint16_t ht, 
    int cclen);

void del_domain(domain_list_t *list, uint8_t *domain, int dlen);

#endif /* __DOMAIN_H__ */
