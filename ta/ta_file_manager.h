/**
 * @file ta_file_manager.h
 * @author Hyunwoo Lee
 * @date 1 Nov 2018
 * @brief This file is to define th file manager that manages the meta
 * information of the cached content
 */

#ifndef __TA_FILE_MANAGER_H__
#define __TA_FILE_MANAGER_H__

#include <openssl/logs.h>
#include "ta_list.h"
#include "ta_defines.h"
#include "ta_edge_cache.h"
#include "ta_key_manager.h"
#include "ta_domain_table.h"
#include "ta_sio.h"
#include "ta_nio.h"

DECLARE_DEFAULT_PARENT_OF(file_manager);
struct file_manager_vops;

struct file_manager_st
{
  DECLARE_DEFAULT_PARENT_FIELDS(file_manager, domain_table);

  struct key_manager_st *key;     // sealing Key
  struct keypair_st *pair;        // asymmetric key pair

  struct fetch_broker_st *broker;
  struct file_manager_vops *vops;   // further functions

  log_t *time_log;
};

struct file_manager_vops
{
  // Get the content information by using the rinfo structure
  struct content_st *(*get)(struct file_manager_st *mngr, struct rinfo *r);

  // Store the content 
  TEE_Result (*store)(struct file_manager_st *mngr, struct io_state_st *io);

  // Anonymize the path
  TEE_Result (*path_generator)(struct content_st *cinfo, struct buf_st *content, 
      struct buf_st *salt);

  // Check the need for cross credentials
  TEE_Result (*check_need_cross_credential)(struct file_manager_st *mngr, struct cmd_st *cctx);
};

// Declare the primitive operations between the file manager and domain tables
DECLARE_LIST_OPS(file_manager, domain_table);

// Declare the unique functions of the file manager
TEE_Result load_device_unique_key(struct key_manager_st **duk);
void free_device_unique_key(struct key_manager_st *duk);

#endif /* __TA_FILE_MANAGER_H__ */
