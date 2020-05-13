#ifndef __TA_FILE_MANAGER_OPS_H__
#define __TA_FILE_MANAGER_OPS_H__

#include "ta_file_manager.h"

static file_manager_vops_t vops =
{
  .check_need_cross_credential = check_need_cross_credential,
};

#endif /* __TA_FILE_MANAGER_OPS_H__ */
