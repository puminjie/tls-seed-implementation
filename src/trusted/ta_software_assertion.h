#ifndef __TA_SOFTWARE_ASSERTION_H__
#define __TA_SOFTWARE_ASSERTION_H__

#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>

#include "ta_defines.h"

#ifdef PLATFORM_OPTEE
int get_optee_seed_digest(uint8_t *buf, uint16_t *ht, size_t *len);
#elif PLATFORM_SGX
int get_sgx_seed_digest(uint8_t *buf, uint16_t *ht, size_t *len);
#endif /* PLATFORM DIGEST */

#endif /* __TA_SOFTWARE_ASSERTION_H__ */
