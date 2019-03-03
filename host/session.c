#include "edge_cache.h"

void prepare_tee_session(struct ec_ctx *ctx)
{
  TEEC_UUID uuid = TA_EDGE_CACHE_UUID;
  uint32_t origin;
  TEEC_Result res;

  EDGE_LOG("Before initialize context");
  res = TEEC_InitializeContext(NULL, &ctx->ctx);
  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
  EDGE_LOG("After initialize context");

  EDGE_LOG("Before open session");
  res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_OpenSession failed with code 0x%x origin 0x%x", res, origin);
  EDGE_LOG("After open session");
}

void terminate_tee_session(struct ec_ctx *ctx)
{
  TEEC_CloseSession(&ctx->sess);
  TEEC_FinalizeContext(&ctx->ctx);
}
