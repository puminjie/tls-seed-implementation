#ifndef __TA_BORINGSSL_AES_H__
#define __TA_BORINGSSL_AES_H__

#include "ta_key_manager.h"

TEE_Result boringssl_encrypt(struct key_manager_st *kst, const uint8_t *iv, uint32_t ivlen, 
    const uint8_t *msg, uint32_t mlen, uint8_t *ciph, uint32_t *clen);
TEE_Result boringssl_decrypt(struct key_manager_st *kst, const uint8_t *iv, uint32_t ivlen, 
    const uint8_t *ciph, uint32_t clen, uint8_t *plain, uint32_t *plen);
TEE_Result boringssl_operation(struct key_manager_st *kst, const uint8_t *iv, uint32_t ivlen,
    const uint8_t *msg1, uint32_t mlen1, uint8_t *msg2, uint32_t *mlen2, uint32_t op);

static struct key_manager_ops bops =
{
  .encrypt = boringssl_encrypt,
  .decrypt = boringssl_decrypt,
};

#endif /* __TA_BORINGSSL_AES_H__ */
