#include "file_io_manager.h"
#include "host_defines.h"

static struct file_io_manager_ops fops;

TEEC_Result init_file_io_manager(struct ec_ctx *ctx, struct file_io_manager_st **mngr, 
    int role, void *log)
{
#ifdef TIME_LOG
  log_t *time_log;
  time_log = (log_t *)log;
#endif /* TIME_LOG */

  (*mngr) = (struct file_io_manager_st *)malloc(sizeof(struct file_io_manager_st));
  memset((*mngr), 0x0, sizeof(struct file_io_manager_st));
  (*mngr)->ctx = ctx;
  (*mngr)->tctx = &(ctx->ctx);

  if (init_iom(&((*mngr)->iom), (*mngr)->tctx, role) < 0)
    return TEEC_ERROR_BAD_STATE;

#ifdef TIME_LOG
  set_op(&((*mngr)->op), (*mngr)->iom, time_log);
#else
  set_op(&((*mngr)->op), (*mngr)->iom, NULL);
#endif /* TIME_LOG */

  (*mngr)->ops = &fops;

  return TEEC_SUCCESS;
}

/** 
 * @brief Organize the data structure of the file information from the command
 * context
 * @param finfo the data structure representing the information about the file
 * @param cctx the command context
 * @return error code
 */
TEEC_Result change_to_file_info(struct finfo *finfo, struct cmd_st *cctx, int op)
{
  EDGE_MSG("Start: change_to_file_info");
  EDGE_LOG("finfo: %p, cctx: %p, op: %d", finfo, cctx, op);

  uint8_t *p;

  // Information from the secure world
  // Length of the path (2 bytes) || Path (path bytes) ||
  // Length of the file (2 bytes) || File (file bytes)
  p = (uint8_t *)(cctx->arg);

  PTR_TO_VAR_2BYTES(p, finfo->plen);
  finfo->path = p;
  p += finfo->plen;

  if (op == FILE_STORE)
  {
    PTR_TO_VAR_2BYTES(p, finfo->flen);
    finfo->data = p;
  }
  else
  {
    finfo->flen = 0;
    finfo->data = NULL;
  }

  EDGE_LOG("finfo->plen: %d, finfo->flen: %d", finfo->plen, finfo->flen);
  EDGE_MSG("Finished: change_to_file_info");
  return TEEC_SUCCESS;
}

/**
 * @brief Generate the file path
 * @param path the path gotten from the secure world
 * @param plen the length of the path
 * @param out the buffer to contain the path
 * @param len the length of the generated path
 * @return error code
 */
TEEC_Result file_path_generator(uint8_t *path, uint32_t plen, uint8_t *out, uint32_t *len)
{
  EDGE_MSG("Start: file_path_generator");
  EDGE_LOG("path: %p, plen: %d, out: %p, len: %p", path, plen, out, len);
  memcpy(out, DEFAULT_DIRECTORY, strlen(DEFAULT_DIRECTORY));
  *len = strlen(DEFAULT_DIRECTORY);
  memcpy(out + *len, "/", 1);
  *len += 1;
  memcpy(out + *len, path, plen);
  *len += plen;
  out[*len] = 0;

  EDGE_MSG("Finished: file_path_generator");
  return TEEC_SUCCESS;
}

/**
 * @brief Load the file from the file system
 * @param finfo the information about the file
 * @param cctx the command context
 * @return error code
 */
TEEC_Result load_file(struct finfo *finfo, struct cmd_st *cctx)
{
  EDGE_MSG("Start: load_file");
  EDGE_LOG("finfo: %p, cctx: %p", finfo, cctx);
  FILE *fp;
  size_t sz;
  uint8_t path[MAX_FILE_NAME_LEN] = {0};
  uint8_t *p;
  uint32_t len;

  file_path_generator(finfo->path, finfo->plen, path, &len);
  //printf("File path to be fetched: %s\n", path);
  //EDGE_PRINT("File path to be fetched", path, 0, len, 10);

  fp = fopen(path, "rb");
  fseek(fp, 0L, SEEK_END);
  sz = ftell(fp);
  fseek(fp, 0L, SEEK_SET);

  p = cctx->arg;

  // Report to the secure world
  // Length of the path (2 bytes) || Path (path bytes) || 
  // Length of the file (2 bytes) || File (file bytes)
  VAR_TO_PTR_2BYTES(finfo->plen, p);
  memcpy(p, finfo->path, finfo->plen);
  //EDGE_PRINT("File path in the NW", p, 0, finfo->plen, 10);
  p += finfo->plen;

  VAR_TO_PTR_2BYTES(sz, p);
  fread(p, 1, sz, fp);
  fclose(fp);
  fp = NULL;
  fflush(NULL);

  cctx->alen = 2 + finfo->plen + 2 + sz;
  EDGE_LOG("cctx->alen: %d", cctx->alen);
  EDGE_MSG("Finished: load_file");

  return TEEC_SUCCESS;
}

/**
 * @brief Store the file from the secure world
 * @param finfo the information about the file
 * @param cctx the command context
 * @return error code
 */
TEEC_Result store_file(struct finfo *finfo, struct cmd_st *cctx)
{
  EDGE_MSG("Start: store_file");
  EDGE_LOG("finfo: %p, cctx: %p, cctx->alen: %d", finfo, cctx, cctx->alen);

  FILE *fp;
  uint8_t path[MAX_FILE_NAME_LEN] = {0};
  uint32_t len, clen;
  uint8_t *p;
  size_t sz;

  EDGE_LOG("cctx->flags (before): %d", cctx->flags);
  file_path_generator(finfo->path, finfo->plen, path, &len);

  //printf("File path to be stored: %s\n", path);
  //EDGE_PRINT("File path to be stored", path, 0, len, 10);

  fp = fopen(path, "wb");
  fwrite(finfo->data, 1, finfo->flen, fp);
  fclose(fp);
  fp = NULL;
  fflush(NULL);

  // Length of path (2 bytes) || Path (path bytes) ||
  // Length of file (2 bytes)
  p = cctx->arg;
  VAR_TO_PTR_2BYTES(finfo->plen, p);
  memcpy(p, finfo->path, finfo->plen);
  p += finfo->plen;

  VAR_TO_PTR_2BYTES(finfo->flen, p);

  cctx->alen = 2 + finfo->plen + 2;

  EDGE_LOG("finfo->plen: %d, finfo->flen: %d", finfo->plen, finfo->flen);
  EDGE_LOG("cctx->flags (after): %d", cctx->flags);
  EDGE_MSG("Finished: store_file");
  return TEEC_SUCCESS;
}

static struct file_io_manager_ops fops = 
{
  .load = load_file,
  .store = store_file,
};
