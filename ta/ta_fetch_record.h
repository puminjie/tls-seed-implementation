#ifndef __TA_FETCH_RECORD_H__
#define __TA_FETCH_RECORD_H__

#include "ta_list.h"

DECLARE_PARENT_OF(fetch_record);
DECLARE_CHILD_OF(requester);

/**
 * @brief Fetch Record: The record contains mapping between the request
 * information and requesters
 */
struct fetch_record_st
{
  // a name field contains a domain name
  DECLARE_DEFAULT_PARENT_FIELDS(fetch_record, requester);
  uint8_t op;
  struct content_st *cinfo;
  struct chunk_st *chunk;          // the current chunk
  struct buf_st *data;
  struct rinfo *r;              // the request info
};

/**
 * @brief Requester: The structure contains the information about requester
 */
struct requester_st
{
  // a name field may contains a content name?
  DECLARE_DEFAULT_CHILD_FIELDS(requester);
  struct tls_context_record_st *sctx;
  //SSL *ssl;
};

DECLARE_LIST_OPS(fetch_record, requester);

#endif /* __TA_FETCH_RECORD_H__ */
