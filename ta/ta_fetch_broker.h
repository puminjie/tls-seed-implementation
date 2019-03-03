#ifndef __TA_FETCH_BROKER_H__
#define __TA_FETCH_BROKER_H__

#include <tee_api.h>
#include <tee_api_types.h>
#include <string.h>
#include <openssl/logs.h>

#include "ta_nio.h"
#include "ta_fetch_record.h"

#define NUM_OF_QUEUES   6

#define WAIT_QUEUE          0
#define PROGRESS_QUEUE      1
#define FINISHED_QUEUE      2
#define WAIT_FILE_QUEUE     3
#define PROGRESS_FILE_QUEUE 4
#define FINISHED_FILE_QUEUE 5

struct fetch_record_st;
struct requester_st;
struct fetch_broker_ops;

/**
 * @brief Fetch Broker: This module gets requests from the TLS frontend manager 
 * to fetch the content from the origin servers.
 */
struct fetch_broker_st
{
  uint32_t lock[NUM_OF_QUEUES];
  uint32_t num[NUM_OF_QUEUES];

  struct fetch_record_st *queue[NUM_OF_QUEUES];
  struct fetch_broker_ops *ops;
  struct file_manager_st *mngr;

  log_t *time_log;
};

/**
 * @brief Fetch Broker's Operation: The operation of the fetch broker
 */
struct fetch_broker_ops
{
  struct fetch_record_st *(*get_by_name)(struct fetch_broker_st *broker, struct buf_st *name,
      int queue);
  struct fetch_record_st *(*get_by_rinfo)(struct fetch_broker_st *broker, struct rinfo *r,
      int queue);
  struct fetch_record_st *(*remove_by_rinfo)(struct fetch_broker_st *broker, struct rinfo *r,
      int queue);
  struct rinfo *(*push_into_queue)(struct fetch_broker_st *broker, struct content_st *cinfo, 
      struct rinfo *r, struct tls_context_record_st *sctx, struct buf_st *buf, uint8_t op);

  TEE_Result (*finished)(struct fetch_broker_st *broker, struct fetch_record_st *record, 
      int queue);
  TEE_Result (*check_finished)(struct fetch_broker_st *broker, struct tls_manager_st *mngr,
      struct tls_context_record_st *sctx);
  TEE_Result (*poll_request)(struct fetch_broker_st *broker, struct cmd_st *cctx, uint8_t queue);
  TEE_Result (*send_response)(struct fetch_broker_st *broker, struct io_status_st *io,
      struct cmd_st *cctx);

  TEE_Result (*process_cmd_load)(struct fetch_broker_st *broker, struct cmd_st *cctx);
  TEE_Result (*process_cmd_store)(struct fetch_broker_st *broker, struct cmd_st *cctx);
};

struct finfo
{
  struct buf_st *path;
  struct buf_st *data;
};

#endif /* __TA_FETCH_BROKER_H__ */
