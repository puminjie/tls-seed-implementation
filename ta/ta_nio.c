#include "ta_nio.h"

struct io_status_st *init_io_status(struct io_status_st **io, struct io_status_ops *ops)
{
  (*io) = (struct io_status_st *)malloc(sizeof(struct io_status_st));
  memset((*io), 0x0, sizeof(struct io_status_st));
  (*io)->flags &= TA_EC_FLAG_INIT;
  (*io)->flags |= TA_EC_FLAG_NEED_PARSE;
  (*io)->finished = 0;
  (*io)->size = 0;
  (*io)->last = 0;
  (*io)->end = 0;
  (*io)->max = BUF_SIZE;
  (*io)->buf = init_alloc_buf_mem(&((*io)->buf), (*io)->max);
  (*io)->ops = ops;

  return (*io);
}

void free_io_status(struct io_status_st *io)
{
  if (io)
  {
    if (io->buf)
      free_buf(io->buf);
    free(io);
    io = NULL;
  }
}

TEE_Result update_data(struct io_status_st *io, uint8_t *buf, uint32_t len)
{
  EDGE_LOG("Update Data: %d bytes, io->buf->len: %d bytes", len, io->buf->len);
  // Only update the buffer when it is available
  if (io->size - io->last >= io->max)
  {
    len = io->max;
  }

  io->last += update_buf_mem(io->buf, 0, buf, len);
  io->end = len;

  // Leave a note that the content is ready to be processed
  if (io->last >= io->size)
    io->flags |= TA_EC_FLAG_NEED_PROCESS;

  return TEE_SUCCESS;
}

void free_rinfo(struct rinfo *r)
{
  if (r)
  {
    if (r->domain)
    {
      r->domain->len = 0;
      if (r->domain->data)
        free(r->domain->data);
      free(r->domain);
    }

    if (r->content)
    {
      r->content->len = 0;
      if (r->content->data)
        free(r->content->data);
      free(r->content);
    }

    free(r);
    r = NULL;
  }
}
