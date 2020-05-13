/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define STR_TRACE_USER_TA "EDGE"

#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <openssl/ssl.h>
#include <stdio.h>
#include <assert.h>
#include <debug.h>

#include <cmds.h>
#include <err.h>

#include <ta_seed.h>
#include <ta_debug.h>

SEED_Result TA_CreateEntryPoint(void)
{
  edmsg("We create entry point!");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
  edmsg("Now we destroy entry point!");
}

SEED_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param  params[4], void **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);


	if (param_types != exp_param_types)
    return TEE_ERROR_BAD_PARAMETERS;

	(void)&params;
	(void)&sess_ctx;

	edmsg("Our session for SEED is open!\n");
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	(void)&sess_ctx;
	edmsg("Our session for SEED is ended!\n");
}

SEED_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
  fstart("sess_ctx: %p, cmd_id: %d, param_types: %d, params: %p", sess_ctx, cmd_id, param_types, (void *) params);

  (void) sess_ctx;

  uint32_t param_none, param_no_logger;
  SEED_Result ret;
  bctx_t *rctx;
  bctx_t *wctx;
  cctx_t *cctx;
#ifdef TIME_LOG
  logger_t *logger;
#endif /* TIME_LOG */

  ret = SEED_SUCCESS;

  param_none = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

  param_no_logger = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT, TEE_PARAM_TYPE_MEMREF_INOUT,
      TEE_PARAM_TYPE_MEMREF_INOUT, TEE_PARAM_TYPE_NONE);

  if (param_types == param_none)
  {
    rctx = NULL;
    wctx = NULL;
    cctx = NULL;
    logger = NULL;
  }
  else if (param_types == param_no_logger)
  {
    rctx = (bctx_t *)params[0].memref.buffer;
    wctx = (bctx_t *)params[1].memref.buffer;
    cctx = (cctx_t *)params[2].memref.buffer;
#ifdef TIME_LOG
    logger = NULL;
#endif /* TIME_LOG */
  }
  else
  {
    rctx = (bctx_t *)params[0].memref.buffer;
    wctx = (bctx_t *)params[1].memref.buffer;
    cctx = (cctx_t *)params[2].memref.buffer;
#ifdef TIME_LOG
    logger = (logger_t *)params[3].memref.buffer;
#endif /* TIME_LOG */
  }

#ifdef TIME_LOG
  ret = seed_main(cmd_id, rctx, wctx, cctx, logger);
#else
  ret = seed_main(cmd_id, rctx, wctx, cctx, NULL);
#endif /* TIME_LOG */

  ffinish("ret: %d", ret);
  return ret;
}
