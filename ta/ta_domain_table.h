#ifndef __TA_DOMAIN_TABLE_H__
#define __TA_DOMAIN_TABLE_H__

#include <inttypes.h>
#include <tee_api.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <openssl/sha.h>
#include <openssl/logs.h>
#include <openssl/x509.h>
#include <stdlib.h>

#include "ta_defines.h"
#include "ta_nio.h"
#include "ta_list.h"
#include "ta_content.h"

DECLARE_PARENT_OF(domain_table);
struct domain_table_vops;

/**
 * @brief structure of a file table that manages particular types of content
 */
struct domain_table_st
{
  // a name field is to contain a domain name
  DECLARE_DEFAULT_PARENT_FIELDS(domain_table, content);

  struct buf_st *cert;            // a certificate of the domain
  struct buf_st *cc;              // a cross credential with the domain

  struct domain_table_vops *vops; // operations of values
};

/**
 * @brief operation of the file table
 */
struct domain_table_vops
{
  TEE_Result (*set_certificate)(struct domain_table_st *tbl, uint8_t *cert, uint32_t clen);
  struct buf_st *(*get_certificate)(struct domain_table_st *tbl);

  TEE_Result (*set_cross_credential)(struct domain_table_st *tbl, uint8_t *cc, uint32_t cclen);
  struct buf_st *(*get_cross_credential)(struct domain_table_st *tbl);
};

DECLARE_LIST_OPS(domain_table, content);

#endif /* __TA_domain_table_H__ */
