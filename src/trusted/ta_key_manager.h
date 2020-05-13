/**
 * @file ta_key_manager.h
 * @author Hyunwoo Lee
 * @date 1 Nov 2018
 * @brief This file is to define the structure of the key manager
 */

#ifndef __TA_KEY_MANAGER_H__
#define __TA_KEY_MANAGER_H__

#ifdef PLATFORM_OPTEE
  #include <inttypes.h>
  #include <tee_internal_api.h>
  #include <tee_internal_api_extensions.h>
#endif /* PLATFORM_OPTEE */
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#ifdef TIME_LOG
  #include <openssl/logger.h>
#endif /* TIME_LOG */
#include "ta_defines.h"

#define TA_OP_ENCRYPT 1
#define TA_OP_DECRYPT 2

#define MAX_PRIVKEY_SIZE 512
#define MAX_CERT_SIZE 1024

typedef struct keypair_st
{
  uint8_t priv[MAX_PRIVKEY_SIZE];
  uint32_t priv_len;
  uint8_t crt[MAX_CERT_SIZE];
  uint32_t crt_len;
} keypair_t;

#endif /* __TA_KEY_MANAGER_H__*/
