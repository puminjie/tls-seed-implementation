#ifndef __TA_TYPES_H__
#define __TA_TYPES_H__

typedef struct bctx_st bctx_t;
typedef struct cctx_st cctx_t;

#ifdef PLATFORM_SGX
typedef struct smem_st smem_t;
typedef struct siom_st siom_t;
#endif /* PLATFORM_SGX */

#endif /* __TA_TYPES_H__ */
