#ifndef __SPX_H__
#define __SPX_H__

#include <edge.h>

#define TLSEXT_TYPE_spx           0x778B

#define SPX_STAGE_NONE                0
#define SPX_STAGE_CLIENT_HELLO        1
#define SPX_STAGE_SERVER_HELLO        2
#define SPX_STAGE_ATTESTATION_REPORT  3
#define SPX_STAGE_SESSION_KEY         4

#endif /* __SPX_H__ */
