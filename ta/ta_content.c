#include "ta_content.h"
#include "ta_nio.h"
#include "ta_buf.h"
#include "ta_digest.h"

IMPLEMENT_DEFAULT_PARENT_FUNC(content, chunk);
IMPLEMENT_DEFAULT_CHILD_FUNC(chunk);

/**
 * @brief Initialize the meta information about the content
 * @param cinfo the meta information about the content
 * @param data additional data (NULL)
 * @return error code
 */
TEE_Result init_content(struct content_st *cinfo, void *data)
{
  EDGE_MSG("Start: init_content");
  EDGE_LOG("cinfo: %p, data: %p", cinfo, data);
  DEFAULT_PARENT_INIT_FUNC(content, cinfo);
  cinfo->salt = init_alloc_buf_mem(&(cinfo->salt), AES_IV_SIZE);
  EDGE_MSG("Finished: init_content");
  return TEE_SUCCESS;
}

/**
 * @brief Free the meta information about the content
 * @param cinfo the meta information to be freed
 * @return error code
 */
TEE_Result free_content(struct content_st *cinfo)
{
  EDGE_MSG("Start: free_content");
  EDGE_LOG("cinfo: %p", cinfo);
  DEFAULT_FREE(cinfo);

  if (cinfo->salt)
  {
    free_buf(cinfo->salt);
  }

  free(cinfo);
  cinfo = NULL;
  EDGE_MSG("Finished: free_content");
  return TEE_SUCCESS;
}

/**
 * @brief Initialize the meta information about the chunk
 * @param chunk the meta informabout about the chunk
 * @param data the additional data (I/O module)
 * @return error code
 */
TEE_Result init_chunk(struct chunk_st *chunk, void *data)
{
  EDGE_LOG("Start: init_chunk: chunk: %p, data: %p", chunk, data);
  int shalen;
  uint8_t h[EVP_MAX_MD_SIZE];
  EVP_MD_CTX *ctx;
  struct io_status_st *io;

  DEFAULT_CHILD_INIT_FUNC(chunk, chunk);

  io = (struct io_status_st *)data;
  chunk->size = io->end;
  chunk->hash = make_digest(io->buf, NULL);

  EDGE_MSG("Finished: init_chunk");
  return TEE_SUCCESS;
}

/**
 * @brief Free the chunk
 * @param chunk the chunk to be freed
 * @return error code
 */
TEE_Result free_chunk(struct chunk_st *chunk)
{
  EDGE_MSG("Start: free_chunk");
  EDGE_LOG("chunk: %p", chunk);
  DEFAULT_FREE(chunk);
  
  if (chunk->hash)
  {
    free_buf(chunk->hash);
  }

  free(chunk);
  chunk = NULL;
  EDGE_MSG("Finished: free_chunk");
  return TEE_SUCCESS;
}
