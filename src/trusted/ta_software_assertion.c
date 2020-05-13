#include <string.h>
#include <debug.h>
#include <assert.h>
#include <err.h>
#include "ta_edge.h"
#include "ta_software_assertion.h"

#ifdef PLATFORM_OPTEE
#include <tee_api_types.h>
#include <tee_api.h>

static TEE_TASessionHandle sess = TEE_HANDLE_NULL;

int get_optee_seed_digest(uint8_t *buf, uint16_t *ht, size_t *len)
{
  efstart("buf: %p, ht: %p, len: %p", buf, ht, (void *)len);
  assert(buf != NULL);
  assert(ht != NULL);
  assert(len != NULL);

  const TEE_UUID uuid = TA_ATTESTATION_UUID;
  TEE_Param params[TEE_NUM_PARAMS];
  uint32_t param_types;
  TEE_Result res;

  if (!sess)
  {
    edmsg("before opening the session with the attestation pseudo TA");
    res = TEE_OpenTASession(&uuid, 0, 0, NULL, &sess, NULL);
    if (res != TEE_SUCCESS)
      return res;
    edmsg("after opening the session with the attestation pseudo TA");
  }

  param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
  memset(params, 0, sizeof(params));
  params[0].memref.buffer = buf;
  params[0].memref.size = EVP_MAX_MD_SIZE;

  edmsg("before invoking the TA command to get the digest of the EC software");
  res = TEE_InvokeTACommand(sess, 0, TA_ATTESTATION_CMD_GET_DIGEST, param_types, params, NULL);
  edmsg("after invoking the TA command to get the digest of the EC software");
  *len = params[0].memref.size;
  edmsg("the length of the digest: %lu", *len);

  switch (*len)
  {
    case SHA_DIGEST_LENGTH:
      *ht = NID_sha1;
      break;
    case SHA224_DIGEST_LENGTH:
      *ht = NID_sha224;
      break;
    case SHA256_DIGEST_LENGTH:
      *ht = NID_sha256;
      break;
    case SHA384_DIGEST_LENGTH:
      *ht = NID_sha384;
      break;
    case SHA512_DIGEST_LENGTH:
      *ht = NID_sha512;
      break;
    default:
      break;
  }

  //TEE_CloseTASession(sess);
  effinish("res: %d", res);
  return res;
}
#elif PLATFORM_SGX
int get_sgx_seed_digest(uint8_t *buf, uint16_t *ht, size_t *len)
{
  efstart("buf: %p, ht: %p, len: %p", buf, ht, len);
  SEED_Result ret;

  *ht = NID_sha256;
  *len = SHA256_DIGEST_LENGTH;
  memcpy(buf, "1", *len);

  ret = SEED_SUCCESS;
  effinish("ret: %d", ret);
  return ret;
}
#endif /* PLATFORM DIGEST */
