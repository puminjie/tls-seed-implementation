#ifndef __SETTING_H__
#define __SETTING_H__

#define BUF_SIZE                16384
#define CBUF_SIZE               16640

#define DEFAULT_PORT_NUMBER     5555
#define DEFAULT_LOG_PREFIX      "log"
#ifdef PLATFORM_VANILA
  #define DEFAULT_LOG_DIRECTORY "log"
#elif PLATFORM_OPTEE
  #define DEFAULT_LOG_DIRECTORY "/usr/htdocs"
#elif PLATFORM_SGX
  #define DEFAULT_LOG_DIRECTORY "log"
#endif /* PLATFORM LOG DIRECTORY */
#define DEFAULT_PATH_LEN        40
#if defined(PLATFORM_VANILA) || defined(PLATFORM_SGX)
  #define DEFAULT_NAME_FILE_PATH  "../../src/logger/seed_names.h"
#else
  #define DEFAULT_NAME_FILE_PATH  "seed_names.h"
#endif /* PLATFORM NAME FILE */

#define DEFAULT_CC_SERVER_PORT  5556
#define DEFAULT_DC_PRIV_NAME    "dc_priv.key"
#define DEFAULT_DC_NAME         "dc.bin"

#define FALLBACK_TEST_NAME      "www.fallback.com"
#define FALLBACK_TEST_PORT      5555

#define SERVER_TEST_NAME        "www.bob.com"
#define SERVER_TEST_PORT        5554

#define MAX_THREADS             40

#define MAX_FILE_NAME_LEN       256
#define MAX_HOST_LEN            256

#ifdef PLATFORM_VANILA
  #define DEFAULT_CERT_PATH     "www.bob.com/cert.der"
  #define DEFAULT_KEY_PATH      "www.bob.com/priv.der"
#endif /* PLATFORM_VANILA */

#ifdef PLATFORM_SGX
  #define DEFAULT_ENCLAVE_PATH  "enclave.signed.so"
#endif /* PLATFORM_SGX */

#define FRONTEND                0
#define BACKEND                 1
#define INITIALIZER             2

#ifndef SUCCESS
#define SUCCESS                 1
#endif /* SUCCESS */

#ifndef FAILURE
#define FAILURE                 0
#endif /* FAILURE */

#define PTR_TO_VAR_2BYTES(p, v) \
  v = (((p[0] & 0xff) << 8) | (p[1] & 0xff)); p += 2;
#define VAR_TO_PTR_2BYTES(v, p) \
  p[0] = (v >> 8) & 0xff; p[1] = (v & 0xff); p += 2;

#define PTR_TO_VAR_3BYTES(p, v) \
  v = (((p[0] & 0xff) << 16) | ((p[1] & 0xff) << 8) | (p[2] & 0xff)); p += 3;
#define VAR_TO_PTR_3BYTES(v, p) \
  p[0] = (v >> 16) & 0xff; p[1] = (v >> 8) & 0xff; p[2] = (v & 0xff); p += 3;


#define PTR_TO_VAR_4BYTES(p, v) \
  v = (((p[0] & 0xff) << 24) | ((p[1] & 0xff) << 16) | ((p[2] & 0xff) << 8) | (p[3] & 0xff)); \
      p += 4;
#define VAR_TO_PTR_4BYTES(v, p) \
  p[0] = (v >> 24) & 0xff; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff; \
      p += 4;

#endif /* __SETTING_H__ */
