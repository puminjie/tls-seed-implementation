#include "spx.h"
#include <debug.h>
#include <assert.h>
#include <err.h>
#include <string.h>
#include <cc.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#define ADD 1
#define SUB 2

typedef struct keypair_st
{
  BIGNUM *pri;
  EC_POINT *pub;
} keypair_t;

typedef struct spx_st
{
  keypair_t *pair;
  uint8_t *shared_key;
  int klen;
} spx_t;

// read callback with the backend spx server
void spx_readcb(struct bufferevent *back, void *ptr)
{
  fstart("back: %p, ptr: %p", back, ptr);
  int ret;
  size_t rlen, wlen;
  client_t *client;
  struct bufferevent *front;
  uint8_t rbuf[BUF_SIZE] = {0, };
  uint8_t wbuf[BUF_SIZE] = {0, };

  client = (client_t *)ptr;
  front = client->front;
  rlen = bufferevent_read(back, rbuf, BUF_SIZE);
  wlen = 0;
  dmsg("rlen: %lu", rlen);
  if (rlen > 0)
  {
    ret = spx_execution(client, rbuf, rlen, wbuf, &wlen);
    dmsg("ret here?: %d", ret);
    dmsg("front: %p", front);
    if (ret == SEED_NEED_WRITE)
    {
      assert(wlen > 0);
      bufferevent_write(front, wbuf, wlen);
    }
  }

  ffinish();
}

// event callback with the backend spx server
void spx_eventcb(struct bufferevent *bev, short events, void *ptr)
{
  fstart("bev: %p, ptr: %p", bev, ptr);

  int ret;
  client_t *client;
  client = (client_t *)ptr;

  if (events & BEV_EVENT_CONNECTED)
  {
    dmsg("Connected to the spx server");
//    ret = bufferevent_write(bev, client->ch, client->chlen);
//    dmsg("send: %d bytes", client->chlen);
//    free(client->ch);
//    client->chlen = -1;
    dmsg("bufferevent_write return: %d", ret);
  }
  else if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF))
  {
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

int make_keypair(keypair_t **pair, EC_GROUP *group, BN_CTX *ctx)
{
  fstart("pair: %p, group: %p, ctx: %p", pair, group, ctx);

  BIGNUM *n = BN_new();
  EC_GROUP_get_order(group, n, ctx);

  (*pair) = (keypair_t *)malloc(sizeof(keypair_t));
  (*pair)->pri = BN_new();
  (*pair)->pub = EC_POINT_new(group);

  BN_rand_range((*pair)->pri, n); //private key
  EC_POINT_mul(group, (*pair)->pub, (*pair)->pri, NULL, NULL, ctx); //public key
  BIGNUM *x, *y;
  x = BN_new();
  y = BN_new();
  EC_POINT_get_affine_coordinates_GFp(group, (*pair)->pub, x, y, ctx);

  ffinish();
  return SEED_SUCCESS;
}

int char_to_pub(unsigned char *input, int klen, EC_POINT *pubkey, EC_GROUP *group, BN_CTX *ctx)
{
  fstart("input: %p, klen: %d, pubkey: %p, group: %p, ctx: %p", input, klen, pubkey, group, ctx);
  int ret;
  ret = EC_POINT_oct2point(group, pubkey, input, klen, ctx);
  ffinish();
  return 1;
}

int pub_to_char(EC_POINT *secret, unsigned char **secret_str, int *slen, EC_GROUP *group, 
    BN_CTX *ctx)
{
  fstart("secret: %p, secret_str: %p, slen: %p, group: %p, ctx: %p", secret, secret_str, slen, group, ctx);
  int key_bytes;

  if (EC_GROUP_get_curve_name(group) == NID_X9_62_prime256v1)
    key_bytes = 256 / 8;
  else
  {
    ferr();
    return -1;
  }

	*slen = 2 * key_bytes + 1;
  (*secret_str) = (unsigned char *)malloc(*slen);
  EC_POINT_point2oct(group, secret, POINT_CONVERSION_UNCOMPRESSED, (*secret_str), (*slen), ctx);

  ffinish();
	return 1;
}

int check_stage(client_t *client, uint8_t *buf, size_t len)
{
  fstart("client: %p, buf: %p, len: %lu", client, buf, len);

  int ret, rt, rlen, ht, hlen;
  uint8_t *p, *end;
  ret = SPX_STAGE_NONE;

  p = buf;
  end = buf + len;
  rt = *(p++);

  if (rt != 22 && rt != 23) 
  {
    emsg("This is not a target message");
    goto out;
  }

  p += 2;
  PTR_TO_VAR_2BYTES(p, rlen);

  // TODO: Need to check
  if (rt == 22)
  {
    ht = *(p++);

    switch (ht)
    {
      case 1:
        dmsg("Client Hello");
        ret = client->state = SPX_STAGE_CLIENT_HELLO;
        break;
      case 2:
        dmsg("Server Hello");
        ret = client->state = SPX_STAGE_SERVER_HELLO;
        break;
      case 16:
        dmsg("Client Key Exchange");
        ret = client->state = SPX_STAGE_ATTESTATION_REPORT;
        break;
      case 20:
        dmsg("Server Finished");
        ret = client->state = SPX_STAGE_SESSION_KEY;
        break;
      default:
        ret = client->state = SPX_STAGE_NONE;
    }
  }
  else if (rt == 23)
  {
    if (client->state == SPX_STAGE_SERVER_HELLO)
      ret = client->state = SPX_STAGE_ATTESTATION_REPORT;
    else if (client->state == SPX_STAGE_ATTESTATION_REPORT)
      ret = client->state = SPX_STAGE_SESSION_KEY;
  }

out:
  ffinish();
  return ret;
}

uint8_t *find_extensions_loc(uint8_t *buf, size_t len)
{
  fstart("buf: %p, len: %lu", buf, len);

  uint8_t *p, *end;
  int rt, type, hlen, slen, clen, colen;

  p = buf;
  end = buf + len;

  // Record Header: content type (1 byte) + version (2 bytes) + length (2 bytes)
  rt = *p;
  dmsg("rt: %d", rt);
  p += 5;
  assert(p < end);

  // handshake type
  type = *(p++);
  assert(p < end);
  dmsg("Handshake message type: %d", type);

  // client hello length
  hlen = *(p++) << 16 | *(p++) << 8 | *(p++);
  if (type == 1)
  {
    dmsg("length of ClientHello: %d bytes", hlen);
  }
  else if (type == 2)
  {
    dmsg("length of ServerHello: %d bytes", hlen);
  }
  else
  {
    emsg("This should not be happened");
    abort();
  }
  assert(p < end);

  // protocol version
  dmsg("protocol version: 0x%x%x", p[0], p[1]);
  p += 2;
  assert(p < end);

  // random
  p += 32;
  assert(p < end);

  // session id
  slen = *(p++);
  dmsg("length of session id: %d bytes", slen);
  p += slen;
  assert(p < end);

  // ciphersuites
  if (type == 1)
  {
    PTR_TO_VAR_2BYTES(p, clen);
    dmsg("bytes of ciphersuites: %d bytes", clen);
    p += clen;
  }
  else if (type == 2)
    p += 2;
  else
  {
    emsg("This should not be happened");
    abort();
  }
  assert(p < end);

  // compression
  if (type == 1)
  {
    colen = *(p++);
    dmsg("bytes of compressions: %d bytes", colen);
    p += colen;
  }
  else if (type == 2)
    p++;
  assert(p < end);

  ffinish();
  return p;
}

int update_length_info(uint8_t *buf, size_t offset, int op)
{
  fstart("buf: %p, offset: %lu", buf, offset);

  assert(op == ADD || op == SUB);

  int ret, rlen, hlen;
  uint8_t *p;

  ret = SEED_SUCCESS;
  p = buf;

  // content type (1 byte) + version (2 bytes)
  p += 3;

  PTR_TO_VAR_2BYTES(p, rlen);
  p -= 2;
  if (op == ADD)
    rlen = rlen + offset;
  else if (op == SUB)
    rlen = rlen - offset;
  VAR_TO_PTR_2BYTES(rlen, p);

  // handshake type 
  p++;
  PTR_TO_VAR_3BYTES(p, hlen);
  p -= 3;
  if (op == ADD)
    hlen = hlen + offset;
  else if (op == SUB)
    hlen = hlen - offset;
  VAR_TO_PTR_3BYTES(hlen, p);

  ffinish();
  return ret;
}

int add_client_hello_spx_extension(client_t *client, uint8_t *buf, size_t len, size_t *wlen)
{
  fstart("client: %p, buf: %p, len: %lu, wlen: %p", client, buf, len, wlen);

  int ret, elen, added, total;
  uint8_t *p, *eloc, *ext;
  ret = SEED_SUCCESS;
  added = 0;

  eloc = find_extensions_loc(buf, len);
  p = eloc;
  PTR_TO_VAR_2BYTES(p, elen);
  p += elen;
  dmsg("bytes of extensions: %d bytes", elen);

  ext = p;
  VAR_TO_PTR_2BYTES(TLSEXT_TYPE_spx, p);
  VAR_TO_PTR_2BYTES(0, p);

  added = p - ext;
  dmsg("added: %d", added);
  total = elen + added;
  dmsg("total: %d", total);
  VAR_TO_PTR_2BYTES(total, eloc);

  *wlen = len + added;
  update_length_info(buf, added, ADD);

  ffinish();
  return ret;
}

#ifdef PLATFORM_VANILA
int add_server_hello_spx_extension(client_t *client, uint8_t *buf, size_t len, size_t *wlen)
{
  fstart("client: %p, buf: %p, len: %lu, wlen: %p", client, buf, len, wlen);

  int ret, offset, pklen, klen, tlen, elen, nid, total;
  size_t slen;
  uint8_t ext[BUF_SIZE];
  uint8_t *p, *q, *r, *s, *lloc, *pstr, *tbs, *sig, *eloc, *pk;
  spx_t *spx;
  keypair_t *pair;
  EC_GROUP *group;
  BN_CTX *ctx;
  BIO *b;
  EVP_PKEY *priv, *pub;
  BUF_MEM *pk_mem;

  ret = SEED_SUCCESS;
  spx = (spx_t *)malloc(sizeof(spx_t));
  memset(spx, 0x0, sizeof(spx_t));
  b = BIO_new(BIO_s_mem());

  offset = 0;
  q = ext;
  VAR_TO_PTR_2BYTES(TLSEXT_TYPE_spx, q);
  offset += 2;
  lloc = q;
  q += 2;

  group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  klen = 2 * 256 / 8 + 1;
  ctx = BN_CTX_new();
  make_keypair(&pair, group, ctx);
  spx->pair = pair;
  client->ptr = (void *)spx;
  pub_to_char(pair->pub, &pstr, &klen, group, ctx);

  nid = NID_sha256;
  tlen = 32 + 2 + klen;
  tbs = (uint8_t *)malloc(tlen);
  memset(tbs, 0, tlen);
  r = tbs;
  RAND_bytes(r, 32);
  r += 32;
  VAR_TO_PTR_2BYTES(klen, r);
  memcpy(r, pstr, klen);
  priv = SSL_get_privatekey(client->ssl);
  pub = X509_get_pubkey(SSL_get_certificate(client->ssl));

  make_signature_block(&sig, tbs, tlen, priv, nid, &slen);

  // OK(1)/Not capable(0) (1 byte) + nonce (32 bytes) 
  // + ephemral key length (2 bytes) + ephemeral key (klen bytes)
  // + signature type (2 bytes) + signature bytes (2 bytes) + signature (slen bytes)
  // + pubkey length (2 bytes) + public key (plen bytes);
  *(q++) = 1;
  memcpy(q, tbs, tlen);
  q += tlen;
  memcpy(q, sig, slen);
  q += slen;
  dprint("Signature", sig, 0, (int)slen, 16);
  PEM_write_bio_PUBKEY(b, pub);
  BIO_get_mem_ptr(b, &pk_mem);
  pk = pk_mem->data;
  pklen = pk_mem->length;
  VAR_TO_PTR_2BYTES(pklen, q);
  memcpy(q, pk, pklen);
  total = 1 + tlen + slen + 2 + pklen;
  VAR_TO_PTR_2BYTES(total, lloc);
  offset = offset + 2 + total;

  dprint("spx extension", ext, 0, offset, 16);
  p = find_extensions_loc(buf, len);
  if (p)
  {
    eloc = p;
    PTR_TO_VAR_2BYTES(p, elen);
    dmsg("elen: %d", elen);
    p += elen;
    s = p;
    memmove(p + offset, p, len - (p - buf));
    memcpy(s, ext, offset);
    elen = elen + offset;
    VAR_TO_PTR_2BYTES(elen, eloc);
  }

  *wlen = len + offset;
  update_length_info(buf, offset, ADD);

  if (tbs)
    free(tbs);
  if (pstr)
    free(pstr);
  if (sig)
    free(sig);
  ffinish();
  return ret;

err:
  if (tbs)
    free(tbs);
  if (pstr)
    free(pstr);
  if (sig)
    free(sig);
  ferr();
  return ret;
}
#endif /* PLATFORM_VANILA */

uint8_t *pop_spx_extension(client_t *client, uint8_t *buf, size_t len, size_t *wlen)
{
  fstart("client: %p, buf: %p, len: %lu, wlen: %p", client, buf, len, wlen);
  
  int type, length, elen, tbr, total, found;
  uint8_t *ret, *p, *eloc, *end, *tmp, *src;

  found = 0;
  end = buf + len;
  eloc = find_extensions_loc(buf, len);
  p = eloc;
  PTR_TO_VAR_2BYTES(p, elen);
  dmsg("Bytes of extensions: %d", elen);
  type = 0;
  length = 0;
  tbr = 0;
  ret = NULL;

  while (p < end)
  {
    tmp = p;
    PTR_TO_VAR_2BYTES(p, type);
    PTR_TO_VAR_2BYTES(p, length);
    if (type == TLSEXT_TYPE_spx)
    {
      dmsg(">>>>> Found TLSEXT_TYPE_spx! <<<<<");
      tbr = tbr + 4 + length;
      found = 1;
      ret = (uint8_t *)malloc(length + 4);
      memcpy(ret, tmp, length + 4);
      break;
    }
    p += length;
  }

  if (!found)
    p = NULL;
  else
  {
    src = tmp + 4 + length;
    dmsg("left: %ld", end - src);
    memmove(tmp, src, end - src);
  }

  total = elen - tbr;
  VAR_TO_PTR_2BYTES(total, eloc);

  *wlen = len - tbr;
  update_length_info(buf, tbr, SUB);

  ffinish();
  return ret;
}

int edge_detect_client_hello(client_t *client, uint8_t *rbuf, size_t rlen, 
    uint8_t *wbuf, size_t *wlen)
{
  fstart("client: %p, rbuf: %p, rlen: %lu, wbuf: %p, wlen: %p", client, rbuf, rlen, wbuf, wlen);
  
  int ret;
  struct event_base *base;
  struct evdns_base *dns_base;
  struct bufferevent *bev;
  const char *name;

  ret = SEED_SUCCESS;

  if (!client->back)
  {
    base = g_ebase[client->idx];
    dns_base = evdns_base_new(base, 1);
    //name = get_servername(buf, len);

    assert(base != NULL);
    bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(bev, spx_readcb, NULL, spx_eventcb, client);
    bufferevent_enable(bev, EV_READ);
    bufferevent_socket_connect_hostname(bev, dns_base, AF_UNSPEC, SERVER_TEST_NAME, 
        SERVER_TEST_PORT);

    client->back = bev;
  }

  dprint("before client hello", rbuf, 0, (int)rlen, 16);
  add_client_hello_spx_extension(client, rbuf, rlen, wlen);
  memcpy(wbuf, rbuf, *wlen);
  dprint("after client hello", wbuf, 0, (int)(*wlen), 16);
//  bufferevent_write(client->back, buf, len);
  if (*wlen > 0)
    ret = SEED_NEED_WRITE;

  ffinish();
  return ret;
}

#ifdef PLATFORM_VANILA
int server_detect_client_hello(client_t *client, uint8_t *buf, size_t len)
{
  fstart("client: %p, buf: %p, len: %lu", client, buf, len);

  int ret, type, length;
  uint8_t *p;
  ret = SEED_SUCCESS;

  type = 0;
  length = 0;

  dprint("before client hello", buf, 0, (int)len, 16);
  p = pop_spx_extension(client, buf, len, &len);
  if (p)
  {
    PTR_TO_VAR_2BYTES(p, type);
    dmsg("type: %x", type);
    PTR_TO_VAR_2BYTES(p, length);
    dmsg("length: %d", length);
  }
  dprint("after client hello", buf, 0, (int)len, 16);

  ffinish();
  return ret;
}
#endif /* PLATFORM_VANILA */

EVP_PKEY *get_peer_pubkey(uint8_t *buf, size_t len)
{
  fstart("buf: %p, len: %lu", buf, len);

  EVP_PKEY *pub;
  int rt, ht, rlen, hlen, found;
  uint8_t *p, *end;

  p = buf;
  end = buf + len;
  found = 0;

  while (p < end)
  {
    rt = *(p++);
    dmsg("record type: %d", rt);
    p += 2;
    PTR_TO_VAR_2BYTES(p, rlen);
    dmsg("record length: %d", rlen);

    if (rt == 22)
    {
      ht = *(p++);
      dmsg("handshake type: %d", ht);
      PTR_TO_VAR_3BYTES(p, hlen);
      dmsg("handshake length: %d", hlen);
      if (ht == 11)
      {
        found = 1;
        break;
      }
      p += hlen;
    }
    else
    {
      p += rlen;
    }
  }

  if (!found)
  {
    emsg("Certificate message is not found");
    goto err;
  }

  ffinish();
  return pub;

err:
  ferr();
  return NULL;
}

int edge_detect_server_hello(client_t *client, uint8_t *rbuf, size_t rlen, 
    uint8_t *wbuf, size_t *wlen)
{
  fstart("client: %p, rbuf: %p, rlen: %lu, wbuf: %p, wlen: %p", client, rbuf, rlen, wbuf, wlen);

  int ret, type, length, result, mlen, klen, slen, plen, nid, tmp;
  uint8_t *p, *msg, *sig;
  spx_t *spx;
  keypair_t *pair;
  EC_GROUP *group;
  BN_CTX *ctx;
  EVP_PKEY *pub;
  BIO *b;

  ret = SEED_SUCCESS;
  type = 0;
  length = 0;
  mlen = slen = 0;
  spx = (spx_t *)malloc(sizeof(spx_t));
  memset(spx, 0x0, sizeof(spx_t));

  group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  ctx = BN_CTX_new();
  make_keypair(&pair, group, ctx);
  spx->pair = pair;

  dprint("before server hello", rbuf, 0, (int)rlen, 16);

//  pub = get_peer_pubkey(buf, len);
//  assert(pub != NULL);

  p = pop_spx_extension(client, rbuf, rlen, wlen);
  if (p)
  {
    PTR_TO_VAR_2BYTES(p, type);
    dmsg("type: %x", type);
    PTR_TO_VAR_2BYTES(p, length);
    dmsg("length: %d", length);

    // OK(1)/Not capable(0) (1 byte) + nonce (32 bytes) 
    // + ephemral key length (2 bytes) + ephemeral key (klen bytes)
    // + signature type (2 byte) + signature bytes (2 bytes) + signature (slen bytes)
    // + public key length (2 bytes) + public key (plen bytes)
    result = *(p++);
    dmsg("Result: %d", result);
    assert(result == 1);
  
    msg = p;
    p += 32;
    mlen += 32;
    PTR_TO_VAR_2BYTES(p, klen);
    mlen += 2;
    p += klen;
    mlen += klen;

    PTR_TO_VAR_2BYTES(p, nid);
    PTR_TO_VAR_2BYTES(p, slen);
    sig = p;
    p += slen;
    PTR_TO_VAR_2BYTES(p, plen);
    b = BIO_new(BIO_s_mem());
    BIO_write(b, p, plen);
    pub = PEM_read_bio_PUBKEY(b, NULL, NULL, NULL);

    dmsg("klen: %d, slen: %d, plen: %d", klen, slen, plen);
    tmp = verify_signature(msg, mlen, nid, slen, sig, pub);
    dmsg("result of verification: %d", tmp);
  }
  dprint("after server hello", rbuf, 0, (int)(*wlen), 16);
  memcpy(wbuf, rbuf, (*wlen));
  ret = SEED_NEED_WRITE;

  ffinish();
  return ret;
}

#ifdef PLATFORM_VANILA
int server_detect_server_hello(client_t *client, uint8_t *buf, size_t len, size_t *wlen)
{
  fstart("client: %p, buf: %p, len: %lu, wlen: %p", client, buf, len, wlen);

  int ret, elen;
  uint8_t *p;
  ret = SEED_SUCCESS;

  ret = add_server_hello_spx_extension(client, buf, len, wlen);

  if (*wlen > 0)
    ret = SEED_NEED_WRITE;

  ffinish();
  return ret;
}
#endif /* PLATFORM_VANILA */

int relay(client_t *client, uint8_t *rbuf, size_t rlen, uint8_t *wbuf, size_t *wlen)
{
  fstart("client: %p, rbuf: %p, rlen: %lu, wbuf: %p, wlen: %p", client, rbuf, rlen, wbuf, wlen);

  int ret;
  struct event_base *base;
  struct evdns_base *dns_base;
  struct bufferevent *bev;

  ret = SEED_NEED_WRITE;
  base = g_ebase[client->idx];
  memcpy(wbuf, rbuf, rlen);
  *wlen = rlen;

  if (!client->back)
  {
    bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(bev, spx_readcb, NULL, spx_eventcb, client);
    bufferevent_enable(bev, EV_READ);
    bufferevent_socket_connect_hostname(bev, dns_base, AF_UNSPEC, 
      SERVER_TEST_NAME, SERVER_TEST_PORT);
    client->back = bev;
  }
  //bufferevent_write(client->back, buf, len);

  ffinish();
  return ret;
}

#ifdef PLATFORM_VANILA
int spx_server_ssl_execution(client_t *client, uint8_t *rbuf, size_t rlen, 
    uint8_t *wbuf, size_t *wlen)
{
  fstart("client: %p, rbuf: %p, rlen: %lu, wbuf: %p, wlen: %p", client, rbuf, rlen, wbuf, wlen);

  int ret, tmp;
  SSL *ssl;
  ret = SEED_SUCCESS;
  ssl = client->ssl;

  assert(ssl != NULL);

  if (SSL_is_init_finished(ssl))
  {
    dmsg("after the spx server TLS session is established");
  }
  else
  {
    dmsg("before the TLS session is established");
    BIO_write(SSL_get_rbio(ssl), rbuf, rlen);
    tmp = SSL_do_handshake(ssl);
    dmsg("tmp: %d", tmp);
    if (tmp == 0)
    {
      dmsg("after the TLS session is established");
      ret = SEED_SUCCESS;
    }

    else if (tmp < 0)
    {
      ERR_print_errors_fp(stderr);
      *wlen = BIO_read(SSL_get_wbio(ssl), wbuf, BUF_SIZE);
      dmsg("wlen: %lu", *wlen);
      if (*wlen > 0)
        ret = SEED_NEED_WRITE;
    }
  }

  ffinish("ret: %d", ret);
  return ret;
}
#endif /* PLATFORM_VANILA */

int spx_execution(client_t *client, uint8_t *rbuf, size_t rlen, uint8_t *wbuf, size_t *wlen)
{
  fstart("client: %p, rbuf: %p, rlen: %lu, wbuf: %p, wlen: %p", client, rbuf, rlen, wbuf, wlen);

  int ret, stage;
  ret = SEED_SUCCESS;

  stage = check_stage(client, rbuf, rlen);

  switch (stage)
  {
    case SPX_STAGE_CLIENT_HELLO:
      if (client->mode == EDGE_MODE_SPX)
        ret = edge_detect_client_hello(client, rbuf, rlen, wbuf, wlen);
#ifdef PLATFORM_VANILA
      else if (client->mode == SERVER_MODE_SPX)
      {
        ret = server_detect_client_hello(client, rbuf, rlen);
        assert(ret == SEED_SUCCESS);
        ret = spx_server_ssl_execution(client, rbuf, rlen, wbuf, wlen);
        assert(ret == SEED_SUCCESS || ret == SEED_NEED_WRITE);
        dprint("before server hello", wbuf, 0, (int)*wlen, 16);
        ret = server_detect_server_hello(client, wbuf, *wlen, wlen);
        client->state = SPX_STAGE_SERVER_HELLO;
        dprint("after server hello", wbuf, 0, (int)*wlen, 16);
        assert(ret == SEED_NEED_WRITE);
      }
#endif /* PLATFORM_VANILA */
      else
      {
        emsg("Invalid mode: Should not be happened");
        ret = SEED_FAILURE;
      }
      break;
    case SPX_STAGE_SERVER_HELLO:
      ret = edge_detect_server_hello(client, rbuf, rlen, wbuf, wlen);
      assert(ret == SEED_NEED_WRITE);
      break;
    case SPX_STAGE_ATTESTATION_REPORT:
      if (client->mode == EDGE_MODE_SPX)
      {
        ret = relay(client, rbuf, rlen, wbuf, wlen);
        //ret = edge_bind_attestation_report(client, wbuf, *wlen, wlen);
      }
#ifdef PLATFORM_VANILA
      else if (client->mode = SERVER_MODE_SPX)
      {
        //ret = server_bind_attestation_report(client, rbuf, rlen);
        ret = spx_server_ssl_execution(client, rbuf, rlen, wbuf, wlen);
        //ret = server_grant_session_key(client, wbuf, *wlen, wlen);
        client->state = SPX_STAGE_SESSION_KEY;
      }
#endif /* PLATFORM_VANILA */
      else
      {
        emsg("Invalid mode: Should not be happened");
        ret = SEED_FAILURE;
      }
      break;
    case SPX_STAGE_SESSION_KEY:
      // TODO: Need to check
      //ret = edge_get_session_key(client, rbuf, rlen);
      ret = relay(client, rbuf, rlen, wbuf, wlen);
      break;
    default:
      if (client->mode == EDGE_MODE_SPX)
        ret = relay(client, rbuf, rlen, wbuf, wlen);
#ifdef PLATFORM_VANILA
      else if (client->mode == SERVER_MODE_SPX)
        ret = spx_server_ssl_execution(client, rbuf, rlen, wbuf, wlen);
#endif /* PLATFORM_VANILA */
      else
      {
        emsg("Invalid mode: Should not be happened");
        ret = SEED_FAILURE;
      }
  }

  ffinish("ret: %d", ret);
  return ret;
}
