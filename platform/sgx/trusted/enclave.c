/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>      /* vsnprintf */
#include <stdarg.h>

#include "enclave.h"
#include "enclave_t.h"  /* print_string */
#include "tSgxSSL_api.h"

#include <openssl/ssl.h>
#include <debug.h>

#include <cmds.h>
#include <err.h>

#include <ta_sio.h>
#include <ta_debug.h>

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void sgx_printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print(buf);
}

unsigned int get_current_seconds()
{
  unsigned int ret;
  ret = 0;
  ocall_get_current_seconds(&ret);
  return ret;
}

unsigned long get_current_time()
{
  unsigned long ret;
  ret = 0;
  ocall_get_current_time(&ret);
  return ret;
}

unsigned long get_current_cpu()
{
  unsigned long ret;
  ret = 0;
  ocall_get_current_cpu(&ret);
  return ret;
}

SEED_Result t_sgxssl_invoke_command(unsigned char cmd_id, void *iom)
{
  efstart("cmd_id: %d, iom: %p", cmd_id, iom);

  assert(cmd_id >= 0);

  SEED_Result ret;
  siom_t *siom;
  bctx_t *rctx;
  bctx_t *wctx;
  cctx_t *cctx;
#ifdef TIME_LOG
  logger_t *logger;
#endif /* TIME_LOG */

  siom = NULL;
  rctx = NULL;
  wctx = NULL;
  cctx = NULL;
#ifdef TIME_LOG
  logger = NULL;
#endif /* TIME_LOG */

  if (iom)
  {
    siom = (siom_t *)iom;
    rctx = (bctx_t *)((smem_t *)(siom->rctx)->buffer);
    wctx = (bctx_t *)((smem_t *)(siom->wctx)->buffer);
    cctx = (cctx_t *)((smem_t *)(siom->cctx)->buffer);
#ifdef TIME_LOG
    logger = (logger_t *)(siom->logger);
    if (logger && !(logger->trusted_time_func))
      logger->trusted_time_func = get_current_time;
    if (logger && !(logger->trusted_cpu_func))
      logger->trusted_cpu_func = get_current_cpu;
#endif /* TIME_LOG */
  }

#ifdef TIME_LOG
  ret = seed_main(cmd_id, rctx, wctx, cctx, logger);
#else
  ret = seed_main(cmd_id, rctx, wctx, cctx, NULL);
#endif /* TIME_LOG */

  effinish();
  return ret;
}
