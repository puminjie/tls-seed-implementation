/**
 * @file ta_file_manager.c
 * @author Hyunwoo Lee
 * @date 1 Nov 2018
 * @brief This file is to implement the functions for the file manager
 */

#include "ta_file_manager.h"
#include "ta_fetch_broker.h"
#include "ta_digest.h"
#include "ta_nio.h"
#include "ta_ec_func.h"
#include "device_unique_key.h"

IMPLEMENT_DEFAULT_PARENT_FUNC(file_manager, domain_table);

TEE_Result load_device_unique_key(struct key_manager_st **kst)
{
  init_key_manager(kst, duk, AES_KEY_SIZE);
  return TEE_SUCCESS;
}

void free_device_unique_key(struct key_manager_st *kst)
{
  free_key_manager(kst);
}

struct buf_st *salted_mac_path_generator(struct buf_st *content, struct buf_st *salt)
{
  return make_digest(content, salt);
}

/**
 * @brief Initialize the structure of the content
 * @param mngr the file manager
 * @param io the I/O structure
 * @return the initialized content structure
 */
struct content_st *init_content_info(struct file_manager_st *mngr, struct io_status_st *io)
{
  struct domain_table_st *dom;
  struct content_st *c;
  struct buf_st *content;

  dom = mngr->ops->get(mngr, io->rinfo->domain);
  c = mngr->ops->get(dom, io->rinfo->content);

  if (c)
  {
    mngr->ops->del(dom, c);
    mngr->ops->free(c);
  }

  if (!c)
  {
    content = init_memcpy_buf_mem(&content, io->rinfo->content->data, io->rinfo->content->len);
    c = mngr->ops->create(dom, content, NULL);
  }

  c->size = io->size;

  TEE_GenerateRandom(c->salt->data, AES_IV_SIZE);
  c->salt->len = AES_IV_SIZE;

  return c;
err:
  return NULL;
}

/**
 * @brief Make the meta information about the content in the secure world and store the content in the normal world
 * @param mngr the file manager
 * @param io the io structure
 * @return SUCCESS/FAILURE
 */
TEE_Result store(struct file_manager_st *mngr, struct io_status_st *io)
{
  EDGE_LOG("Start: Store: mngr: %p, io: %p", mngr, io);
  struct content_st *cinfo;
  struct domain_table_st *dom;
  struct buf_st *buf, *path;


  cinfo = mngr->vops->get(mngr, io->rinfo);

  if (!cinfo)
  {
    EDGE_LOG("The content is not cached");
    cinfo = init_content_info(mngr, io);
  }
  else
  {
    EDGE_LOG("The content is cached. We are going to add a chunk");
  }

  io->data = (void *)(cinfo->salt);
  path = make_alphabetic_path(io->buf, cinfo->salt);
  cinfo->ops->create(cinfo, path, io); // create a chunk

  init_alloc_buf_mem(&buf, BUF_SIZE);
#ifndef NO_SEALING
  mngr->key->ops->encrypt(mngr->key, cinfo->salt->data, cinfo->salt->len,
      io->buf->data, io->end, buf->data, &(buf->len));
#else
  printf("io->end: %d\n", io->end);
  memcpy(buf->data, io->buf->data, io->end);
  buf->len = io->end;
#endif /* NO_SEALING */
  //EDGE_PRINT("Original Message", io->buf->data, 0, io->buf->len, 10);
  //EDGE_PRINT("Encrypted File", buf->data, 0, buf->len, 10);

  mngr->broker->ops->push_into_queue(mngr->broker, cinfo, io->rinfo, NULL, buf, FILE_STORE);

  EDGE_MSG("Finished: Store");
  return TEE_SUCCESS;
}

/**
 * @brief Check if the EC needs to get the CC from the origin domain
 * @param mngr the file manager
 * @param cctx the command structure
 * @return SUCCESS/FAILURE
 */
TEE_Result check_need_cross_credential(struct file_manager_st *mngr, struct cmd_st *cctx)
{
  EDGE_MSG("[TA] check_need_cross_credential");
  struct domain_table_st *ptr;
  struct buf_st *name;
  cctx->flags = TA_EDGE_CACHE_NXT_EXIT;

  if (mngr->num <= 0) goto err;
  ptr = mngr->head;
  
  while (ptr)
  {
    if (!ptr->cc)
    {
      EDGE_LOG("CC is not set: ptr: %p", ptr);
      EDGE_LOG("ptr->get_name: %p", ptr->get_name);
      name = ptr->get_name(ptr);
      EDGE_LOG("name: %p", name);
      EDGE_LOG("name->len: %p", name->len);
      if (name->len > 0)
      {
        EDGE_LOG("Get CC is needed: %s", name->data);
        cctx->flags = TA_EDGE_CACHE_NXT_GET_CC;
      }
      set_address(cctx, name, DEFAULT_CC_PORT);
      break;
    }
  }

  return TEE_SUCCESS;
err:
  return TEE_ERROR_BAD_STATE;
}

/**
 * @brief Get the information about the content
 * @param mngr the file manager
 * @param r the request information structure
 * @return the structure of the content
 */
struct content_st *get_content_info(struct file_manager_st *mngr, struct rinfo *r)
{
  EDGE_LOG("Start: get_content_info: mngr: %p, r: %p", mngr, r);
  struct domain_table_st *dom;
  
  dom = mngr->ops->get(mngr, r->domain);
  EDGE_LOG("Finished: get_content_info");
  return dom->ops->get(dom, r->content);
}

static struct file_manager_vops vops = 
{
  .store = store,
  .path_generator = salted_mac_path_generator,
  .check_need_cross_credential = check_need_cross_credential,
  .get = get_content_info,
};

TEE_Result init_file_manager(struct file_manager_st **mngr, struct cmd_st *cctx, void *time_log)
{
  EDGE_MSG("init file manager");

  uint8_t buf[BUF_SIZE];
  uint8_t *p;
  uint32_t blen, sz;
  struct key_manager_st *duk, *sk;
  const uint8_t iv[] = "0000000000000000";
  uint8_t iv1[AES_IV_SIZE];
  uint8_t iv2[AES_IV_SIZE];
  memset(buf, 0x0, BUF_SIZE);
  
  if (cctx->flags != TA_EDGE_CACHE_CMD_INIT)
    return TEE_ERROR_BAD_PARAMETERS;

  (*mngr) = (struct file_manager_st *)TEE_Malloc(sizeof(struct file_manager_st), 
      TEE_MALLOC_FILL_ZERO);
  DEFAULT_PARENT_INIT_FUNC(file_manager, (*mngr));
  (*mngr)->vops = &vops;
  EDGE_LOG("=========== (*mngr): %p, (*mngr)->ops: %p, (*mngr)->vops: %p ==========", 
      (*mngr), (*mngr)->ops, (*mngr)->vops);

  blen = MAX_KEY_LENGTH;
  load_device_unique_key(&duk);

  EDGE_PRINT("Loaded Device Unique Key", duk->key, 0, duk->klen, 10);

  // Sealing key length (2 bytes) || encrypted sealing key ||
  // Metainfo length (2 bytes) || encrypted meta info ||
  // Private key length (2 bytes) || encrypted private key ||
  // Certificate length (2 bytes) || encrypted certificate
  p = cctx->arg;
  PTR_TO_VAR_2BYTES(p, sz);

  EDGE_LOG("The size of the sealed key length: %d", sz);
  EDGE_PRINT("Sealed Key", p, 0, sz, 10);
  EDGE_PRINT("IV to be used", iv, 0, AES_IV_SIZE, 10);
  duk->ops->decrypt(duk, iv, AES_IV_SIZE, p, sz, buf, &blen);
  p += sz;
  
  free_device_unique_key(duk);

  EDGE_PRINT("Decrypted Sealing Key", buf, 0, blen, 10);
  init_key_manager(&((*mngr)->key), buf, AES_KEY_SIZE);

  EDGE_PRINT("Unsealed Sealing Key", (*mngr)->key->key, 0, (*mngr)->key->klen, 10);
  EDGE_MSG("Setting sealing key success");

  memset(buf, 0x0, BUF_SIZE);
  sk = (*mngr)->key;
  sz = p[0] << 8 | p[1]; p += 2;
  sk->ops->decrypt(sk, iv, AES_IV_SIZE, p, sz, buf, &blen);
  p += sz;
  buf[blen + 1] = 0;

  EDGE_LOG("Meta Info: %s", buf);
  memcpy(iv1, buf, AES_IV_SIZE);
  memcpy(iv2, buf + AES_IV_SIZE + 1, AES_IV_SIZE);

  EDGE_PRINT("IV for private key", iv1, 0, AES_IV_SIZE, 10);
  EDGE_PRINT("IV for certificate", iv2, 0, AES_IV_SIZE, 10);

  (*mngr)->pair = (struct keypair_st *)malloc(sizeof(struct keypair_st));
  PTR_TO_VAR_2BYTES(p, sz);
  sk->ops->decrypt(sk, iv1, AES_IV_SIZE, p, sz, (*mngr)->pair->priv, &((*mngr)->pair->priv_len));
  p += sz;

  PTR_TO_VAR_2BYTES(p, sz);
  sk->ops->decrypt(sk, iv2, AES_IV_SIZE, p, sz, (*mngr)->pair->crt, &((*mngr)->pair->crt_len));
  p += sz;
  
  EDGE_PRINT("EC Private key", (*mngr)->pair->priv, 0, (*mngr)->pair->priv_len, 10);
  EDGE_PRINT("EC Certificate", (*mngr)->pair->crt, 0, (*mngr)->pair->crt_len, 10);

  if (time_log)
    (*mngr)->time_log = (log_t *)time_log;

  EDGE_MSG("Configures the operation success");

  return TEE_SUCCESS;
err:
  return TEE_ERROR_OUT_OF_MEMORY;
}

