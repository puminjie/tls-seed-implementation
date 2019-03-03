#ifndef __TA_NIO_H__
#define __TA_NIO_H__

#include <stdint.h>
#include "ta_defines.h"
#include "ta_file_manager.h"

#define TA_EC_FLAG_INIT             0x0
#define TA_EC_FLAG_REQUEST_RCVD     0x1
#define TA_EC_FLAG_REQUEST_SENT     0x2

#define TA_EC_FLAG_CONTENT_LOAD     0x4
#define TA_EC_FLAG_CONTENT_STORE    0x8

#define TA_EC_FLAG_RESPONSE_RCVD    0x10
#define TA_EC_FLAG_RESPONSE_FORWARD 0x20

#define TA_EC_FLAG_NEED_PARSE       0x40
#define TA_EC_FLAG_NEED_PROCESS     0x80

/**
 *@brief Request Info
 */
struct rinfo
{
  struct buf_st *domain;          // the information about the requested domain
  struct buf_st *content;         // the information about the requested content
};

/**
 * @brief I/O status structure
 */
struct io_status_st
{
  uint8_t flags;                  // flags
  uint8_t finished;

  uint32_t size;                  // the size of the content (Content-Length in HTTP header)
  uint32_t last;                  // the received size currently
  uint32_t end;                   // the buffer offset
  uint32_t hdrlen;                // the length of the header

  struct buf_st *buf;             // the temoporary buffer for the content
  uint32_t max;                   // the maximum size of the buffer

  struct buf_st *header;          // the HTTP header

  struct io_status_ops *ops;      // the I/O operation
  struct rinfo *rinfo;
  void *data;                     // the further data, if needed
};

/**
 * @brief I/O status operation
 */
struct io_status_ops
{
  TEE_Result (*send_request)(struct io_status_st *io, struct tls_context_record_st *sctx, 
      struct file_manager_st *mngr, struct cmd_st *cctx);
  TEE_Result (*send_response)(struct io_status_st *io, struct tls_context_record_st *sctx);
  TEE_Result (*parse_data)(struct io_status_st *io, uint8_t *buf, uint32_t len);
  TEE_Result (*update_data)(struct io_status_st *io, uint8_t *buf, uint32_t len);
  TEE_Result (*process_data)(struct io_status_st *io, struct tls_context_record_st *sctx, 
      struct file_manager_st *mngr, struct cmd_st *cctx);
  TEE_Result (*read)(struct io_status_st *io, uint8_t *buf, uint32_t *len);
  TEE_Result (*write)(struct io_status_st *io, uint8_t *buf, uint32_t *len);
};

struct io_status_st *init_io_status(struct io_status_st **io, struct io_status_ops *ops);
void free_io_status(struct io_status_st *io);
TEE_Result update_data(struct io_status_st *io, uint8_t *buf, uint32_t len);
void free_rinfo(struct rinfo *r);

#endif /* __TA_NIO_H__ */
