/**
 * @file ta_defines.h
 * @author Hyunwoo Lee
 * @date 1 Nov 2018
 * @brief This file is to define constants used in this project
 */

#ifndef __TA_DEFINES_H__
#define __TA_DEFINES_H__

#ifdef PLATFORM_OPTEE
  #include <tee_api.h>
#endif /* PLATFORM_OPTEE */

#define BUF_SIZE            16384
#define CBUF_SIZE           16640 // 16384 bytes (TLS record maximum size) + 256 (additional)

#define AES_KEY_SIZE        16
#define AES_IV_SIZE         16

#define MAX_KEY_LENGTH      32
#define MAX_CACHE_SIZE      8192
#define MAX_RECORDS         100
#define MAX_HOST_LEN        256

#define DEFAULT_ORIGIN_PORT 5555
#define DEFAULT_CC_PORT     5556

#define AUTHORITY_NAME      "www.edgeplatform.com"
#define AUTHORITY_PORT      1234
#define AUTHORITY_ABS_PATH  "/list"

#define FRONTEND  0
#define BACKEND   1

#define NONE 0
#define CONTRACTOR 1
#define NON_CONTRACTOR 2

#define PTR_TO_VAR_2BYTES(p, v) \
  v = (((p[0] & 0xff) << 8) | (p[1] & 0xff)); p += 2;
#define VAR_TO_PTR_2BYTES(v, p) \
  p[0] = (v >> 8) & 0xff; p[1] = (v & 0xff); p += 2;

#define PTR_TO_VAR_4BYTES(p, v) \
  v = (((p[0] & 0xff) << 24) | ((p[1] & 0xff) << 16) | ((p[2] & 0xff) << 8) | (p[3] & 0xff)); \
      p += 4;
#define VAR_TO_PTR_4BYTES(v, p) \
  p[0] = (v >> 24) & 0xff; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff; \
      p += 4;

#ifdef PLATFORM_OPTEE
  typedef TEE_Result SEED_Result;
#elif PLATFORM_SGX
  typedef int SEED_Result;
#endif /* PLATFORM RETURN TYPE */

#endif /* __TA_DEFINES_H__ */
