#ifndef __TA_FETCH_BROKER_H__
#define __TA_FETCH_BROKER_H__

#include <tee_api.h>
#include <tee_api_types.h>
#include <string.h>

#include "ta_defines.h"
#include "ta_nio.h"
#include "ta_list.h"
#include "ta_file_record.h"

DECLARE_PARENT_OF(file_broker);
struct file_broker_vops;

/**
 * @brief Fetch Broker: This module gets requests from the TLS frontend manager 
 * to fetch the content from the origin servers.
 */
struct file_broker_st
{
  DECLARE_DEFAULT_PARENT_FIELDS(file_broker, file_record);
  struct file_broker_vops *vops;
};

/**
 * @brief Fetch Broker's Operation: The operation of the fetch broker
 */
struct file_broker_vops
{
  TEE_Result (*poll_io)(struct file_broker_st *broker, struct cmd_st *cctx);
  TEE_Result (*push_io)(struct file_broker_st *broker, struct io_status_st *io,
      struct cmd_st *cctx);
};

#endif /* __TA_FETCH_BROKER_H__ */
