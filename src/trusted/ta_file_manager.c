/**
 * @file ta_file_manager.c
 * @author Hyunwoo Lee
 * @date 1 Nov 2018
 * @brief This file is to implement the functions for the file manager
 */

#include "ta_file_manager.h"
#include <err.h>
#include <debug.h>
#include <cmds.h>
#include "ta_ec_func.h"

IMPLEMENT_DEFAULT_PARENT_FUNC(file_manager, domain_table);

/**
 * @brief Check if the EC needs to get the CC from the origin domain
 * @param mngr the file manager
 * @param cctx the command structure
 * @return SUCCESS/FAILURE
 */
SEED_Result check_need_cross_credential(file_manager_t *mngr, cctx_t *cctx)
{
  efstart("mngr: %p, cctx: %p", mngr, cctx);
  domain_table_t *ptr;
  buf_t *name;
  cctx->flags = TA_EDGE_NXT_EXIT;

  if (mngr->num <= 0) 
  {
    emsg("The number of domains registered is %d", mngr->num);
    goto err;
  }
  ptr = mngr->head;
  
  while (ptr)
  {
    name = ptr->name;

    if (!ptr->cc)
    {
      edmsg("CC is not set: ptr: %p", ptr);
      name = ptr->name;
      
      if (name->max > 0)
      {
        edmsg("Get CC is needed: %s", name->data);
        cctx->flags = TA_EDGE_NXT_GET_CC;
        cctx->stage = TA_EDGE_GET_CC_INIT;
      }
      set_address(cctx, name, DEFAULT_CC_PORT);
      break;
    }

    ptr = ptr->next;
  }

  effinish();
  return SEED_SUCCESS;
err:
  eferr();
  return SEED_ERROR_BAD_STATE;
}
