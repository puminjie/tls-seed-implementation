#ifndef __TA_DOMAIN_TABLE_H__
#define __TA_DOMAIN_TABLE_H__

#include <openssl/sha.h>
#include <openssl/x509.h>
#include <stdlib.h>

#ifdef TIME_LOG
  #include <openssl/logger.h>
#endif /* TIME_LOG */

#ifdef PLATFORM_OPTEE
  #include <inttypes.h>
  #include <tee_api.h>
  #include <tee_internal_api.h>
  #include <tee_internal_api_extensions.h>
#endif /* PLATFORM_OPTEE */

#include "ta_defines.h"
#include "ta_list.h"

DECLARE_CHILD_OF(domain_table);
typedef struct domain_table_vops domain_table_vops_t;

/**
 * @brief structure of a file table that manages particular types of content
 */
struct domain_table_st
{
  // a name field is to contain a domain name
  DECLARE_DEFAULT_CHILD_FIELDS(domain_table);

  buf_t *cert;            // a certificate of the domain
  buf_t *cc;              // a cross credential with the domain

  domain_table_vops_t *vops; // operations of values
};

/**
 * @brief operation of the file table
 */
struct domain_table_vops
{
  SEED_Result (*set_certificate)(domain_table_t *tbl, uint8_t *cert, uint32_t clen);
  buf_t *(*get_certificate)(domain_table_t *tbl);

  SEED_Result (*set_cross_credential)(domain_table_t *tbl, uint8_t *cc, uint32_t cclen);
  buf_t *(*get_cross_credential)(domain_table_t *tbl);
};

#endif /* __TA_domain_table_H__ */
