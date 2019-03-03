#include "ta_boringssl_aes.h"

TEE_Result init_key_manager(struct key_manager_st **kst, const uint8_t *key, uint32_t klen)
{
  TEE_Result res;
  struct aes_cipher *enc, *dec;

  (*kst) = (struct key_manager_st *)malloc(sizeof(struct key_manager_st));
  EDGE_PRINT("Key to be used", key, 0, klen, 10);
  memcpy((*kst)->key, key, klen);
  (*kst)->klen = klen;
  (*kst)->ops = &bops;

  return TEE_SUCCESS;
}

void free_key_manager(struct key_manager_st *kst)
{
  free(kst);
}
