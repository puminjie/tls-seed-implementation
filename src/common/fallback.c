#include "fallback.h"
#include <debug.h>
#include <assert.h>
#include <err.h>
#include <signal.h>

// read callback with the backend fallback server
void fb_readcb(struct bufferevent *back, void *ptr)
{
  fstart("back: %p, ptr: %p", back, ptr);
  size_t rlen;
  client_t *client;
  struct bufferevent *front;
  uint8_t rbuf[BUF_SIZE] = {0, };

  client = (client_t *)ptr;
  front = client->front;
  rlen = bufferevent_read(back, rbuf, BUF_SIZE);
  dmsg("rlen: %lu", rlen);
  if (rlen > 0)
  {
    dmsg("front: %p", front);
    bufferevent_write(front, rbuf, rlen);
  }

  ffinish();
}

// event callback with the backend fallback server
void fb_eventcb(struct bufferevent *bev, short events, void *ptr)
{
  fstart("bev: %p, ptr: %p", bev, ptr);

  client_t *client;
  client = (client_t *)ptr;

  if (events & BEV_EVENT_CONNECTED)
  {
    dmsg("Connected to the fallback server");
    bufferevent_write(bev, client->ch, client->chlen);
    dprint("ClientHello", client->ch, 0, client->chlen, 16);
  }
  else if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF))
  {
    dmsg("Connection error or eof");
    int err = bufferevent_socket_get_dns_error(bev);
    if (err)
    {
      emsg("DNS error: %s", evutil_gai_strerror(err));
    }
    client->bclose = 1;
    bufferevent_free(bev);
    client->back = NULL;

    if (client->fclose)
      free_client_ctx(client);
  }
  ffinish();
}

void set_client_fallback(client_t *ctx)
{
  fstart("ctx: %p", ctx);

  struct event_base *base;
  struct evdns_base *dns_base;
  struct bufferevent *bev;
#ifdef PLATFORM_VANILA
  const char *name;
  SSL *ssl;
  ssl = ctx->ssl;
  name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
#elif defined(PLATFORM_OPTEE) || defined(PLATFORM_SGX)
  hiom_t *hiom;
  cctx_t *cctx;
  uint8_t host[MAX_HOST_LEN];
  uint16_t port;

  hiom = ctx->frontend->iom;
  cctx = get_cmd_ctx(hiom);
  get_fallback(ctx, cctx->arg, cctx->alen, host, &port);
#endif /* PLATFORM */
  base = g_ebase[ctx->idx];
  dns_base = evdns_base_new(base, 1);

  assert(base != NULL);
  bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
  bufferevent_setcb(bev, fb_readcb, NULL, fb_eventcb, ctx);
  bufferevent_enable(bev, EV_READ);
#ifdef PLATFORM_VANILA
  bufferevent_socket_connect_hostname(bev, dns_base, AF_UNSPEC, 
      FALLBACK_TEST_NAME, FALLBACK_TEST_PORT);
#elif defined(PLATFORM_OPTEE) || defined(PLATFORM_SGX)
  //bufferevent_socket_connect_hostname(bev, dns_base, AF_UNSPEC, (unsigned char *)host, port);
  if (ctx->fb_server)
  {
    dmsg("fallback server: %s", ctx->fb_server);
    bufferevent_socket_connect_hostname(bev, dns_base, AF_UNSPEC, 
        ctx->fb_server, 443);
  }
  else
  {
    bufferevent_socket_connect_hostname(bev, dns_base, AF_UNSPEC, 
        FALLBACK_TEST_NAME, FALLBACK_TEST_PORT);
  }
#endif /* PLATFORM */

#ifdef PLATFORM_VANILA
  SSL_shutdown(ssl);
  SSL_free(ssl);
  ctx->ssl = NULL;
#elif defined(PLATFORM_OPTEE) || defined(PLATFORM_SGX)
  if (ctx->frontend)
  {
    free_iom(ctx->frontend->iom);
    free(ctx->frontend);
    ctx->frontend = NULL;
  }

  if (ctx->backend)
  {
    free_iom(ctx->backend->iom);
    free(ctx->backend);
    ctx->backend = NULL;
  }
#endif /* PLATFORM */

  ctx->back = bev;
  ctx->fallback = 1;

  event_base_dispatch(base);

  ffinish();
}

int fallback_execution(client_t *client, uint8_t *rbuf, size_t rlen, 
    uint8_t *wbuf, size_t *wlen)
{
  fstart("client: %p, rbuf: %p, rlen: %lu, wbuf: %p, wlen: %p", client, rbuf, rlen, wbuf, wlen);
  int ret;
  ret = SEED_SUCCESS;

  if (rlen > 0)
  {
    ret = SEED_NEED_WRITE;
    wbuf = rbuf;
    *wlen = rlen;
  }

  ffinish();
  return ret;
}
