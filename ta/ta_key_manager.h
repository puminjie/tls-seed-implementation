/**
 * @file ta_key_manager.h
 * @author Hyunwoo Lee
 * @date 1 Nov 2018
 * @brief This file is to define the structure of the key manager
 */

#ifndef __TA_KEY_MANAGER_H__
#define __TA_KEY_MANAGER_H__

#include <inttypes.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/logs.h>
#include "ta_defines.h"

#define TA_OP_ENCRYPT 1
#define TA_OP_DECRYPT 2

#define MAX_PRIVKEY_SIZE 512
#define MAX_PUBKEY_SIZE 1024

struct key_manager_ops;
struct key_manager_st
{
  uint8_t key[MAX_KEY_LENGTH];
  uint32_t klen;
  struct key_manager_ops *ops; 
};

struct key_manager_ops
{
  TEE_Result (*encrypt)(struct key_manager_st *kst, const uint8_t *iv, uint32_t ivlen, 
      const uint8_t *msg, uint32_t mlen, uint8_t *ciph, uint32_t *clen);
  TEE_Result (*decrypt)(struct key_manager_st *kst, const uint8_t *iv, uint32_t ivlen, 
      const uint8_t *ciph, uint32_t clen, uint8_t *plain, uint32_t *plen);
};

struct keypair_st
{
  uint8_t priv[MAX_PRIVKEY_SIZE];
  uint32_t priv_len;
  uint8_t crt[MAX_PUBKEY_SIZE];
  uint32_t crt_len;
};

TEE_Result init_key_manager(struct key_manager_st **kst, const uint8_t *key, uint32_t klen);
void free_key_manager(struct key_manager_st *kst);

#endif /* __TA_KEY_MANAGER_H__*/
