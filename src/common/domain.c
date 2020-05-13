#include <domain.h>
#include <debug.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

domain_list_t *init_domain_list(void)
{
  fstart();
  domain_list_t *ret;
  ret = NULL;

  ret = (domain_list_t *)malloc(sizeof(domain_list_t));
  if (!ret)
  {
    emsg("Out of memory");
    goto err;
  }
  memset(ret, 0x0, sizeof(domain_list_t));

  ffinish("ret: %p", ret);
  return ret;

err:
  if (ret)
    free(ret);

  ferr();
  return FAILURE;
}

void free_domain_list(domain_list_t *list)
{
  fstart("list: %p", list);
  assert(list != NULL);

  domain_t *head, *curr;

  head = list->head;
  do {
    curr = head;
    head = curr->next;
    free_domain(curr);
  } while (head);

  free(list);
  ffinish();
}

void print_domain_list(domain_list_t *list)
{
  fstart("list: %p", list);
  assert(list != NULL);

  domain_t *curr;
  curr = list->head;

  while (curr)
  {
    if (curr->domain)
    {
      dmsg("Domain (%d bytes): %s", curr->dlen, curr->domain);
    }

    if (curr->cert)
    {
      dmsg("Certificate (%d bytes):\n%s", curr->clen, curr->cert);
    }

    if (curr->cc)
    {
      dprint("Cross Credential", curr->cc, 0, curr->cclen, 16);
    }

    curr = curr->next;
  }

  ffinish();
}

domain_t *init_domain(void)
{
  fstart();
  domain_t *ret;
  ret = NULL;

  ret = (domain_t *)malloc(sizeof(domain_t));
  if (!ret) 
  {
    emsg("Out of memory");
    goto err;
  }
  memset(ret, 0x0, sizeof(domain_t));

  ffinish("ret: %p", ret);
  return ret;

err:
  if (ret)
    free(ret);
  ferr();
  return NULL;
}

void free_domain(domain_t *dom)
{
  fstart("dom: %p", dom);

  if (dom)
  {
    if (dom->domain)
    {
      free(dom->domain);
      dom->domain = NULL;
    }
    dom->dlen = -1;

    if (dom->cert)
    {
      free(dom->cert);
      dom->cert = NULL;
    }
    dom->clen = -1;

    if (dom->cc)
    {
      free(dom->cc);
      dom->cc = NULL;
    }
    dom->cclen = -1;
    dom->next = NULL;
  }

  ffinish();
}

domain_t *find_domain(domain_list_t *list, uint8_t *domain, int dlen)
{
  fstart("list: %p, domain: %s, dlen: %d", list, domain, dlen);

  domain_t *ret, *curr;
  ret = NULL;
  curr = list->head;

  while (curr)
  {
    if ((curr->dlen == dlen) && !strncmp((const char *)curr->domain, (const char *)domain, dlen))
    {
      ret = curr;
      break;
    }
    curr = curr->next;
  }

  ffinish("ret: %p", ret);
  return ret;
}

int add_domain_cert(domain_list_t *list, uint8_t *domain, int dlen, uint8_t *cert, int clen)
{
  fstart("list: %p, domain: %s, dlen: %d, cert: %p, clen: %d", list, domain, dlen, cert, clen);
  assert(list != NULL);
  assert(domain != NULL);
  assert(dlen > 0);

  int ret, found;
  domain_t *dom;

  found = TRUE;
  ret = SUCCESS;
  dom = find_domain(list, domain, dlen);
  if (!dom)
  {
    dom = init_domain();
    found = FALSE;
  }

  if (found == TRUE && dom->domain)
    free(dom->domain);
  dom->domain = (uint8_t *)malloc(dlen + 1);
  if (!dom->domain)
  {
    emsg("Out of memory");
    goto err;
  }
  memcpy(dom->domain, domain, dlen);
  dom->domain[dlen] = 0;
  dom->dlen = dlen;

  if (found == TRUE && dom->cert)
  {
    free(dom->cert);
    dom->cert = NULL;
  }

  if (cert && clen > 0)
  {
    dom->cert = (uint8_t *)malloc(clen + 1);
    if (!dom->cert)
    {
      emsg("Out of memory");
      goto err;
    }
    memcpy(dom->cert, cert, clen);
    dom->cert[clen] = 0;
    dom->clen = clen;
  }

  if (found == FALSE)
  {
    if (list->head)
      dom->next = list->head;
    list->head = dom;
  }

  ffinish("ret: %d", ret);
  return ret;

err:
  ferr();
  return FAILURE;
}

int add_domain_cc(domain_list_t *list, uint8_t *domain, int dlen, uint8_t *cc, uint16_t ht, 
    int cclen)
{
  fstart("list: %p, domain: %s, dlen: %d, cc: %p, ht: %d, cclen: %d", list, domain, dlen, cc, ht, cclen);
  assert(list != NULL);
  assert(domain != NULL);
  assert(dlen > 0);
  assert(cc != NULL);
  assert(ht > 0);
  assert(cclen > 0);

  domain_t *dom;

  dom = find_domain(list, domain, dlen);
  if (!dom) 
  {
    emsg("No domain found: %s", domain);
    goto err;
  }

  dom->cc = (uint8_t *)malloc(cclen + 1);
  memcpy(dom->cc, cc, cclen);
  dom->cc[cclen] = 0;
  dom->ht = ht;
  dom->cclen = cclen;

  ffinish();
  return SUCCESS;

err:
  ferr("ret: %d", FAILURE);
  return FAILURE;
}

void del_domain(domain_list_t *list, uint8_t *domain, int dlen)
{
  fstart("list: %p, domain: %s, dlen: %d", list, domain, dlen);

  domain_t *prev, *curr;

  prev = NULL;
  curr = list->head;

  while (curr)
  {
    if ((curr->dlen == dlen) && !strncmp((const char *)curr->domain, (const char *)domain, dlen))
    {
      if (!prev)
        list->head = curr->next;
      else
        prev->next = curr->next;
      free_domain(curr);
      break;
    }
    prev = curr;
    curr = curr->next;
  }

  ffinish();
}
