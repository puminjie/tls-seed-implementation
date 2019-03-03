#ifndef __TA_CONTENT_H__
#define __TA_CONTENT_H__

#include <inttypes.h>
#include "ta_list.h"

DECLARE_CHILD_OF(chunk);
DECLARE_PARENT_OF(content);

/**
 * @brief structure of a record that is inserted in the table
 */
struct content_st
{
  // a name field contains the content name
  DECLARE_DEFAULT_PARENT_FIELDS(content, chunk);

//  struct buf_st *header;    // the HTTP header
//  struct buf_st *hpath;     // the path of the HTTP header
  struct buf_st *salt;      // the salt used to seal the content
  uint32_t size;            // the total size of the content

  uint8_t cached;     // the flag to represent whether the content is cached in the secure world
  uint8_t *cache;     // the pointer to the cache in the secure world
  uint8_t idx;        // the index in the cache
  uint8_t start_pos;  // the starting position of the content
  uint8_t clen;       // the length of the content cached in the secure world
};

/**
 * @brief the information of the file path
 */
struct chunk_st
{
  // a name field is to contain the path of the chunk
  DECLARE_DEFAULT_CHILD_FIELDS(chunk);

  uint32_t size;     // the end offset of the chunk
  struct content_st *cinfo; // the content info

  struct buf_st *hash;  // the digest of the chunk (not salted, not needed)
};

DECLARE_LIST_OPS(content, chunk);

#endif /* __TA_CONTENT_H__ */
