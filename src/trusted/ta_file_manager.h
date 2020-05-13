/**
 * @file ta_file_manager.h
 * @author Hyunwoo Lee
 * @date 1 Nov 2018
 * @brief This file is to define th file manager that manages the meta
 * information of the cached content
 */

#ifndef __TA_FILE_MANAGER_H__
#define __TA_FILE_MANAGER_H__

#ifdef TIME_LOG
  #include <openssl/logger.h>
#endif /* TIME_LOG */
#include "ta_list.h"
#include "ta_defines.h"
#include "ta_domain_table.h"
#include "ta_sio.h"
#include "ta_key_manager.h"

DECLARE_PARENT_OF(file_manager);

typedef struct file_manager_vops
{
  // Check the need for cross credentials
  SEED_Result (*check_need_cross_credential)(file_manager_t *mngr, cctx_t *cctx);
} file_manager_vops_t;

struct file_manager_st
{
  DECLARE_DEFAULT_PARENT_FIELDS(file_manager, domain_table);

  keypair_t *pair;

  file_manager_vops_t *vops;   // further functions
#ifdef TIME_LOG
  logger_t *logger;
#endif /* TIME_LOG */
};


// Declare the primitive operations between the file manager and domain tables
DECLARE_LIST_OPS(file_manager, domain_table);

SEED_Result check_need_cross_credential(file_manager_t *mngr, cctx_t *cctx);
#endif /* __TA_FILE_MANAGER_H__ */
