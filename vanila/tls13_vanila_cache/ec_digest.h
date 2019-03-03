#ifndef __EC_DIGEST_H__
#define __EC_DIGEST_H__

#include <openssl/sha.h>

#define EC_DIGEST_LEN SHA256_DIGEST_LENGTH

uint8_t ec_digest[] = {
  0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
  0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2,
  0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
  0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2
};

#endif /* __EC_DIGEST_H__ */