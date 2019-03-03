#ifndef __TA_SOFTWARE_ASSERTION_H__
#define __TA_SOFTWARE_ASSERTION_H__

#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>

#include "ta_defines.h"

int get_ec_digest(uint8_t *buf, uint16_t *ht, size_t *len);

#endif /* __TA_SOFTWARE_ASSERTION_H__ */
