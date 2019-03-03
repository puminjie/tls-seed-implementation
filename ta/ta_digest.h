#ifndef __TA_DIGEST_H__
#define __TA_DIGEST_H__

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/logs.h>
#include "ta_buf.h"

static uint8_t code[32] = 
{ 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
  'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
  'y', 'z'};

/**
 * @brief Make the digest with the salt
 * @param content the content to be hashed
 * @param salt the random value to make the hash value diversed
 * @return the buffer that contains the hash value with its length
 */
static inline struct buf_st *make_digest(struct buf_st *content, struct buf_st *salt)
{
  EDGE_LOG("Start: make_digest: content: %p, salt: %p", content, salt);
  int shalen;
  uint8_t h[EVP_MAX_MD_SIZE];
  struct buf_st *hash;
  EVP_MD_CTX *ctx;

  ctx = EVP_MD_CTX_create();

  EVP_DigestInit(ctx, EVP_sha256());

  if (salt)
    EVP_DigestUpdate(ctx, salt->data, salt->len);

  EVP_DigestUpdate(ctx, content->data, content->len);
  EVP_DigestFinal(ctx, h, &shalen);

  hash = init_memcpy_buf_mem(&hash, h, shalen);

  EDGE_MSG("Finished: make_digest");
  return hash;
}

/**
 * @brief Make the path based on salted MAC with the Base64 encoding scheme (RFC4648)
 * @param content the content to be hashed
 * @param salt the random value to make the hash value diversed
 * @return the buffer that contains the hash value with its length
 */
static inline struct buf_st *make_alphabetic_path(struct buf_st *content, struct buf_st *salt)
{
  EDGE_LOG("Start: make_digest: content: %p, salt: %p", content, salt);
  int shalen, i;
  uint8_t h[EVP_MAX_MD_SIZE];
  struct buf_st *hash;
  uint8_t *p, *q;
  EVP_MD_CTX *ctx;

  ctx = EVP_MD_CTX_create();

  EVP_DigestInit(ctx, EVP_sha256());

  if (salt)
    EVP_DigestUpdate(ctx, salt->data, salt->len);

  EVP_DigestUpdate(ctx, content->data, content->len);
  EVP_DigestFinal(ctx, h, &shalen);

  hash = init_alloc_buf_mem(&hash, 2 * shalen);

  p = hash->data;
  q = h;

  for (i=0; i<shalen; i++, q++)
  {
    (*p++) = code[(*q >> 4) & 0xf];
    (*p++) = code[*q & 0xf];
  }
  hash->len = 2 * shalen;

  //EDGE_PRINT("path to be stored", hash->data, 0, hash->len, 10);

  EDGE_MSG("Finished: make_digest");
  return hash;
}

#endif /* __TA_DIGEST_H__ */
