#ifndef __FILE_IO_MANAGER_H__
#define __FILE_IO_MANAGER_H__

#include <stdio.h>
#include "hio.h"
#include "host_defines.h"
#include "edge_cache.h"

struct file_io_manager_ops;

struct finfo
{
  uint16_t plen;
  uint8_t *path;
  uint16_t flen;
  uint8_t *data;
};

struct file_io_manager_st
{
  struct ec_ctx *ctx;
  struct hiom_st *iom;
  TEEC_Context *tctx;
  TEEC_Operation op;
  struct file_io_manager_ops *ops;
};

struct file_io_manager_ops
{
  TEEC_Result (*load)(struct finfo *finfo, struct cmd_st *cctx);
  TEEC_Result (*store)(struct finfo *finfo, struct cmd_st *cctx);
};

TEEC_Result init_file_io_manager(struct ec_ctx *ctx, struct file_io_manager_st **mngr, 
    int role, void *log);
TEEC_Result change_to_file_info(struct finfo *finfo, struct cmd_st *cctx, int op);
#endif /* __FILE_IO_MANAGER_H__ */
