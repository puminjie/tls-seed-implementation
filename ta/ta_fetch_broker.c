/**
 * @file ta_fetch_broker.c
 * @author Hyunwoo Lee
 * @date 1 Nov 2018
 * @brief This file is to define functions in the fetch broker
 */

#include <openssl/ssl.h>
#include "ta_fetch_broker.h"
#include "ta_tls_manager.h"
#include "ta_init.h"
#include "ta_ec_func.h"
#include "ta_debug.h"

#ifdef DEBUG
#define PRINT_QUEUE(queue) print_queue(broker, queue)
#else
#define PRINT_QUEUE(queue)
#endif /* DEBUG */

static TEE_Result add_record_to_queue(struct fetch_broker_st *broker,
    struct fetch_record_st *record, int queue);
static TEE_Result del_record_from_queue(struct fetch_broker_st *broker,
    struct fetch_record_st *record, int queue);
TEE_Result set_file_cctx(struct cmd_st *cctx, struct fetch_record_st *record);
TEE_Result get_file_cctx(struct cmd_st *cctx, struct finfo *finfo, int op);

static char *qname[NUM_OF_QUEUES] =
{
  "WAIT_QUEUE",
  "PROGRESS_QUEUE",
  "FINISHED_QUEUE",
  "WAIT_FILE_QUEUE",
  "PROGRESS_FILE_QUEUE",
  "FINISHED_FILE_QUEUE"
};

/**
 * @brief Initialize the fetch record
 * @param record the record to be initialized
 * @param data the additional data
 * @return error code
 */
TEE_Result init_fetch_record(struct fetch_record_st *record, void *data)
{
  (void) data;

  DEFAULT_PARENT_INIT_FUNC(fetch_record, record);

  return TEE_SUCCESS;
}

void free_fetch_record(struct fetch_record_st *record)
{
  if (record)
  {
    if (record->data)
    {
      free_buf(record->data);
    }
    free(record);
    record = NULL;
  }
}

/**
 * @brief Get the record from the queue by the domain name
 * @param broker the fetch broker
 * @param name the domain name for searching
 * @param queue the queue
 * @return the target fetch record
 */
struct fetch_record_st *get_fetch_record_from_queue_by_name(struct fetch_broker_st *broker, 
    struct buf_st *name, int queue)
{
  EDGE_MSG("Start: get_fetch_record_from_queue_by_name");
  EDGE_LOG("broker: %p / name: %p / queue: %d", broker, name, queue);

  struct fetch_record_st *curr;

  EDGE_MSG("get fetch record from queue by name 2");
  if (broker->num[queue] <= 0)
    return NULL;

  EDGE_MSG("get fetch record from queue by name 3");
  if (queue != FINISHED_QUEUE && queue != FINISHED_FILE_QUEUE)
  {
    while (broker->lock[queue]) {}
    broker->lock[queue] = 1;
  }
  curr = broker->queue[queue];

  EDGE_MSG("get fetch record from queue by name 4");
  EDGE_LOG("broker->queue[%d]: %p", queue, broker->queue[queue]);
  EDGE_LOG("curr->name: %p", curr->name);
  EDGE_LOG("curr->name->data (%d bytes): %s", curr->name->len, curr->name->data);

  while (curr)
  {
    if (curr->name->len == name->len)
    {
      if (!strncmp(curr->name->data, name->data, name->len))
      {
        EDGE_LOG("Found rinfo with %s", curr->name->data);
        break;
      }
    }
    curr = curr->next;
  }

  EDGE_MSG("get fetch record from queue by name 5");
  if (queue != FINISHED_QUEUE && queue != FINISHED_FILE_QUEUE)
    broker->lock[queue] = 0;

  EDGE_MSG("Finished: get_fetch_record_from_queue_by_name");
  return curr;
}

/**
 * @brief Get the record from the queue by the domain name
 * @param broker the fetch broker
 * @param content the content name for searching
 * @param queue the queue
 * @return the target fetch record
 */
struct fetch_record_st *get_fetch_record_from_queue_by_content(struct fetch_broker_st *broker, 
    struct buf_st *content, int queue)
{
  EDGE_MSG("Start: get_fetch_record_from_queue_by_content");
  EDGE_LOG("broker: %p / content: %p / queue: %d", broker, content, queue);

  struct fetch_record_st *curr;

  if (broker->num[queue] <= 0)
    return NULL;

  if (queue != FINISHED_QUEUE && queue != FINISHED_FILE_QUEUE)
  {
    while (broker->lock[queue]) {}
    broker->lock[queue] = 1;
  }
  curr = broker->queue[queue];

  EDGE_LOG("broker->queue[%d]: %p", queue, broker->queue[queue]);

  while (curr)
  {
    if (curr->r->content->len == content->len)
    {
      if (!strncmp(curr->r->content->data, content->data, content->len))
      {
        EDGE_LOG("Found rinfo with %s", curr->r->content->data);
        break;
      }
    }
    
    curr = curr->next;
  }

  if (queue != FINISHED_QUEUE && queue != FINISHED_FILE_QUEUE)
    broker->lock[queue] = 0;

  EDGE_MSG("Finished: get_fetch_record_from_queue_by_content");
  return curr;
}


/**
 * @brief Get the record from the queue by the domain name
 * @param broker the fetch broker
 * @param r the request information
 * @param queue the queue
 * @return the target fetch record
 */
struct fetch_record_st *get_fetch_record_from_queue_by_rinfo(struct fetch_broker_st *broker, 
    struct rinfo *r, int queue)
{
  EDGE_MSG("Start: get_fetch_record_from_queue_by_rinfo");
  EDGE_LOG("broker: %p / rinfo: %p / queue: %d", broker, r, queue);

  struct fetch_record_st *curr;

  if (broker->num[queue] <= 0)
    return NULL;

  if (queue != FINISHED_QUEUE && queue != FINISHED_FILE_QUEUE)
  {
    while (broker->lock[queue]) {}
    broker->lock[queue] = 1;
  }
  curr = broker->queue[queue];
  EDGE_LOG("curr: %p, curr->r: %p", curr, curr->r);

  while (curr && curr->r)
  {
    if (curr->r == r)
    {
      break;
    }
    
    curr = curr->next;
  }

  if (queue != FINISHED_QUEUE && queue != FINISHED_FILE_QUEUE)
    broker->lock[queue] = 0;

  if (curr)
  {
    EDGE_LOG("Fetched Record: %p", curr);
    EDGE_LOG("Related rinfo: %p, Argument rinfo: %p", curr->r, r);
    EDGE_LOG("Record head: %p", curr->head);
  }
  else
    EDGE_MSG("No record is found");

  EDGE_MSG("Finished: get_fetch_record_from_queue_by_rinfo");
  return curr;
}

/**
 * @brief Get the record from the queue by the domain name
 * @param broker the fetch broker
 * @param content the content name for searching
 * @param queue the queue
 * @return the target fetch record
 */
struct fetch_record_st *get_fetch_record_from_queue_by_path(struct fetch_broker_st *broker, 
    struct buf_st *path, int queue, struct fetch_record_st *record, int op)
{
  EDGE_MSG("Start: get_fetch_record_from_queue_by_path");
  EDGE_LOG("broker: %p / path: %p / queue: %d", broker, path, queue);

  //EDGE_PRINT("Path for searching", path->data, 0, path->len, 10);

  struct fetch_record_st *curr;

  if (broker->num[queue] <= 0)
    return NULL;

  if (queue != FINISHED_QUEUE && queue != FINISHED_FILE_QUEUE)
  {
    while (broker->lock[queue]) {}
    broker->lock[queue] = 1;
  }

  if (!record)
  {
    curr = broker->queue[queue];
  }
  else
  {
    while (curr)
    {
      if (curr == record && curr->op == record->op)
        break;
      curr = curr->next;
    }

    if (curr->next)
      curr = curr->next;
    else
      curr = NULL;

  }

  while (curr)
  {
    if (curr->chunk->name->len == path->len)
    {
      if (!strncmp(curr->chunk->name->data, path->data, path->len))
      {
        break;
      }
    }
    curr = curr->next;
  }

  if (queue != FINISHED_QUEUE && queue != FINISHED_FILE_QUEUE)
    broker->lock[queue] = 0;

  EDGE_MSG("Finished: get_fetch_record_from_queue_by_path");
  return curr;
}

/**
 * @brief Remove the record from the queue by the request information
 * @param broker the fetch broker
 * @param r the request information
 * @param queue the queue
 * @return the target fetch record
 */
struct fetch_record_st *remove_fetch_record_from_queue_by_rinfo(struct fetch_broker_st *broker, 
    struct rinfo *r, int queue)
{
  EDGE_MSG("Start: remove_fetch_record_from_queue_by_rinfo");
  EDGE_LOG("broker: %p / rinfo: %p / queue: %d", broker, r, queue);

  struct fetch_record_st *curr;

  if (broker->num[queue] <= 0)
    return NULL;

  if (queue != FINISHED_QUEUE && queue != FINISHED_FILE_QUEUE)
  {
    while (broker->lock[queue]) {}
    broker->lock[queue] = 1;
  }
  curr = broker->queue[queue];
  EDGE_LOG("curr: %p, curr->r: %p", curr, curr->r);

  while (curr && curr->r)
  {
    if (curr->r == r)
    {
      if (curr->prev)
        curr->prev->next = curr->next;
      else
        broker->queue[queue] = curr->next;

      break;
    }
    
    curr = curr->next;
  }

  if (queue != FINISHED_QUEUE && queue != FINISHED_FILE_QUEUE)
    broker->lock[queue] = 0;

  if (curr)
  {
    EDGE_LOG("Fetched Record: %p", curr);
    EDGE_LOG("Related rinfo: %p, Argument rinfo: %p", curr->r, r);
    EDGE_LOG("Record head: %p", curr->head);
  }
  else
    EDGE_MSG("No record is found");

  EDGE_MSG("Finished: remove_fetch_record_from_queue_by_rinfo");
  return curr;
}

#ifdef DEBUG
/**
 * @brief Print all the records in the particular queue
 * @param broker the fetch broker
 * @param queue the queue index
 */
void print_queue(struct fetch_broker_st *broker, int queue)
{
  struct fetch_record_st *curr;
  EDGE_MSG("");
  EDGE_LOG("===== Records in the %s =====", qname[queue]);

  if (broker->num[queue] <= 0)
  {
    EDGE_LOG("Nothing is in the queue");
  }
  else
  {
    curr = broker->queue[queue];
    while (curr)
    {
      EDGE_LOG("Record: %p, op: %d, cinfo: %p, chunk: %p, data: %p, rinfo: %p", 
          curr, curr->op, curr->cinfo, curr->chunk, curr->data, curr->r);
      curr = curr->next;
    }
  }

  EDGE_MSG("=============================");
  EDGE_MSG("");
}
#endif /* DEBUG */

/**
 * @brief Push the record into the queue
 * @param broker the fetch broker
 * @param r the data structure for request
 * @param ssl the ssl object
 * @return the ticket number for the fetch record
 */
struct rinfo *push_into_queue(struct fetch_broker_st *broker, struct content_st *cinfo, 
    struct rinfo *r, struct tls_context_record_st *sctx, struct buf_st *buf, uint8_t op)
{
  EDGE_LOG("Start: push_into_queue: broker: %p, r: %p, sctx: %p, buf: %p, op: %d", 
      broker, r, sctx, buf, op);
  int in_queue = 0;
  uint8_t ret;
  struct fetch_record_st *record;
  struct requester_st *requester;
  record = NULL;

/* TODO: For simultaneous requests
  if (op == FETCH_FROM_ORIGIN)
  {
    record = get_fetch_record_from_queue_by_content(broker, r->content, WAIT_QUEUE);
    if (record)
      in_queue = 1;
  }
  else
  {
    record = get_fetch_record_from_queue_by_content(broker, r->content, WAIT_FILE_QUEUE);
    if (record && record->op == op)
      in_queue = 1;
    else
      record = NULL;
  }
*/

  if (!record)
  {
    EDGE_MSG("Make the fetch record");
    INIT_LIST(fetch_record, record, NULL);
    record->name = init_buf_mem(&(record->name), r->domain->data, r->domain->len);
    record->r = r;
    record->op = op;

    if ((op == FILE_LOAD) || (op == FILE_STORE))
    {
      record->cinfo = cinfo;
      record->chunk = cinfo->head;
    }

    if (op == FILE_STORE)
    {
      // We will store the last chunk added
      while (record->chunk->next)
        record->chunk = record->chunk->next;
      record->data = buf;
    }
  }
  
  EDGE_LOG("Make Requester: Requested Domain (%d bytes): %s / Content (%d bytes): %s",
      record->r->domain->len, record->r->domain->data, record->r->content->len, 
      record->r->content->data);

  if (op != FILE_STORE)
  {
    requester = record->ops->create(record, r->content, (void *)sctx);
  }

  if (!in_queue)
  {
    if (op == FETCH_FROM_ORIGIN)
    {
      EDGE_LOG("Before add record to %s", qname[WAIT_QUEUE]);
      add_record_to_queue(broker, record, WAIT_QUEUE);
      //PRINT_QUEUE(WAIT_QUEUE);
    }
    else
    {
      EDGE_LOG("Before add record to %s", qname[WAIT_FILE_QUEUE]);
      add_record_to_queue(broker, record, WAIT_FILE_QUEUE);
      //PRINT_QUEUE(WAIT_FILE_QUEUE);
    }
  }

  EDGE_MSG("Finished: push_into_queue");
  return record->r;
}

/**
 * @brief Pop the fetch record from the queue
 * @param broker the fetch broker
 * @return the target fetch record
 */
struct fetch_record_st *pop_from_queue(struct fetch_broker_st *broker, int queue)
{
  EDGE_MSG("Start: pop_from_queue");
  EDGE_LOG("broker: %p, queue: %d", broker, queue);

  struct fetch_record_st *ret;
  ret = NULL;

  if (broker->num[queue] > 0)
  {
    ret = broker->queue[queue];

    EDGE_LOG("Before del record from %s", qname[queue]);
    //PRINT_QUEUE(queue);
    del_record_from_queue(broker, ret, queue);
    EDGE_LOG("After del record from %s", qname[queue]);

    EDGE_LOG("Before add_record to %s", qname[queue + 1]);
    //PRINT_QUEUE(queue + 1);
    add_record_to_queue(broker, ret, queue + 1);
    EDGE_LOG("After add_record to %s", qname[queue + 1]);
    //PRINT_QUEUE(queue + 1);

    EDGE_LOG("Before del record from %s", qname[queue]);
    //PRINT_QUEUE(queue);
    del_record_from_queue(broker, ret, queue);
    EDGE_LOG("After del record from %s", qname[queue]);
    //PRINT_QUEUE(queue);
  }

  EDGE_MSG("Finished: pop_from_queue");
  return ret;
}

/**
 * @brief Remove the requester's information from the fetch record
 * @param broker Fetch broker
 * @param record Fetch record which contains the requester's information
 * @param ticket Ticket number
 * @param queue Queue number
 * @return Error code
 */
TEE_Result finalize_request(struct fetch_broker_st *broker, struct fetch_record_st *record, 
    int queue)
{
  EDGE_LOG("Start: finalize_request: broker: %p, record: %p, queue: %d",
      broker, record, queue);

  record->num--;

  if (record->num <= 0)
  {
    //PRINT_QUEUE(queue);
    del_record_from_queue(broker, record, queue);
    if (queue == FINISHED_FILE_QUEUE)
      free_fetch_record(record);
    //PRINT_QUEUE(queue);
  }

  EDGE_MSG("Finished: finalize_request");
  return TEE_SUCCESS;
}

/**
 * @brief Finalize the request and move the fetch record into the finished
 * queue
 * @param broker the fetch broker
 * @param record the fetch record to be moved
 * @param queue the queue to be inserted
 * @return error code
 */
TEE_Result finished(struct fetch_broker_st *broker, struct fetch_record_st *record, int queue)
{
  EDGE_LOG("Start: finished: broker: %p, record: %p", broker, record);

  if (!record)
    return TEE_ERROR_BAD_STATE;

  EDGE_LOG("Before add record to %s", qname[queue]);
  //PRINT_QUEUE(queue);
  add_record_to_queue(broker, record, queue);
  EDGE_LOG("After add record to %s", qname[queue]);
  //PRINT_QUEUE(queue);

  EDGE_LOG("Before del record from %s", qname[queue]);
  //PRINT_QUEUE(queue - 1);
  del_record_from_queue(broker, record, queue - 1);
  EDGE_LOG("After del record from %s", qname[queue]);
  //PRINT_QUEUE(queue - 1);

  EDGE_MSG("Finished: finished");

  return TEE_SUCCESS;
}

/**
 * @brief Make a new request for the next chunk
 * @param broker the fetch broker
 * @param record the fetch record to be moved
 * @param queue the queue to be inserted
 * @return error code
 */
TEE_Result next_chunk(struct fetch_broker_st *broker, struct fetch_record_st *record, int queue)
{
  EDGE_LOG("Start: next_chunk: broker: %p, record: %p, queue: %d", broker, record, queue);
  
  if (!record)
    return TEE_ERROR_BAD_STATE;

  EDGE_LOG("Before add record to %s", qname[queue]);
  //PRINT_QUEUE(queue);
  add_record_to_queue(broker, record, queue);
  EDGE_LOG("After add record to %s", qname[queue]);
  //PRINT_QUEUE(queue);

  EDGE_LOG("Before del record from %s", qname[PROGRESS_FILE_QUEUE]);
  //PRINT_QUEUE(queue - 1);
  del_record_from_queue(broker, record, PROGRESS_FILE_QUEUE);
  EDGE_LOG("After del record from %s", qname[PROGRESS_FILE_QUEUE]);
  //PRINT_QUEUE(queue - 1);
 

  EDGE_MSG("Finished: next_chunk");
}

/**
 * @brief Check whether the request is processed
 * @param broker the fetch broker
 * @param mngr the TLS context manager
 * @param ssl the SSL object
 * @return error code (1 for finished, 0 for not finished)
 */
int check_finished(struct fetch_broker_st *broker, struct tls_manager_st *mngr,
    struct tls_context_record_st *sctx)
{
  EDGE_LOG("Start: check_finished: broker: %p, mngr: %p, sctx: %p", broker, mngr, sctx);
  int ret;
  struct io_status_st *io;
  struct rinfo *r;
  struct fetch_record_st *record;

  ret = 0;

  io = (struct io *) sctx->status;
  record = broker->ops->get_by_rinfo(broker, io->rinfo, FINISHED_QUEUE);
  
  if (record)
  {
    finalize_request(broker, record, FINISHED_QUEUE);
    sctx->status->finished = 1;
    ret = 1;
  }

  record = NULL;
  record = broker->ops->get_by_rinfo(broker, io->rinfo, FINISHED_FILE_QUEUE);

  if (record)
  {
    finalize_request(broker, record, FINISHED_FILE_QUEUE);
    sctx->status->finished = 1;
    ret = 1;
  }

  EDGE_MSG("Finished: check_finished");
  return ret;
}

/**
 * @brief Poll whether the request is come from the frontend
 * @param broker the fetch broker
 * @param cctx the context for the command
 * @return error code
 */
TEE_Result poll_request(struct fetch_broker_st *broker, struct cmd_st *cctx, int queue)
{
  struct fetch_record_st *record;

  EDGE_LOG("Start: poll_request: broker: %p, cctx: %p, queue: %d", broker, cctx, queue);

  EDGE_LOG("Before pop from %s", qname[queue]);
  //PRINT_QUEUE(queue);

  record = pop_from_queue(broker, queue);

  EDGE_LOG("After pop from %s", qname[queue]);
  //PRINT_QUEUE(queue);

  if (record)
  {
    if (record->op == FETCH_FROM_ORIGIN)
    {
      EDGE_LOG("Found Record: Request to %s for %s", record->r->domain->data, 
          record->r->content->data);
      set_address(cctx, record->r->domain, DEFAULT_ORIGIN_PORT);
      cctx->flags = TA_EDGE_CACHE_NXT_GET_DATA_INIT;
      EDGE_MSG("Set command for data fetch from origin");
    }
    else
    {
      EDGE_LOG("Found Record for FILE_LOAD/STORE");

      if (record->op == FILE_LOAD)
      {
        set_file_cctx(cctx, record);
        cctx->flags = TA_EDGE_CACHE_NXT_LOAD;
        EDGE_MSG("Set command for load succeed");
      }
      else if (record->op == FILE_STORE)
      {
        set_file_cctx(cctx, record);
        cctx->flags = TA_EDGE_CACHE_NXT_STORE;
        EDGE_MSG("Set command for store succeed");
      }
    }
  }
  else
  {
    EDGE_MSG("Nothing is found for Request");
    if (queue == WAIT_QUEUE)
      cctx->flags = TA_EDGE_CACHE_NXT_POLL_FETCH;
    else if (queue == WAIT_FILE_QUEUE)
      cctx->flags = TA_EDGE_CACHE_NXT_POLL_IO;
    else
      return TEE_ERROR_BAD_STATE;
  }
  EDGE_LOG("Next Command is set to %s", cmd_to_str(cctx->flags));
  EDGE_MSG("Finished: poll_request");
  
  return TEE_SUCCESS;
}

/**
 * @brief Set the file command into the command context
 * @param cctx the command context
 * @param record the file record
 */
TEE_Result set_file_cctx(struct cmd_st *cctx, struct fetch_record_st *record)
{
  EDGE_MSG("Started: set_file_cctx");
  EDGE_LOG("cctx: %p, record: %p", cctx, record);

  uint8_t *p;
  memset(cctx->arg, 0x0, cctx->max);
  p = cctx->arg;

  // Length of the path (2 bytes) || Path (path bytes) ||
  // Length of the file (2 bytes) || File (file bytes)
  VAR_TO_PTR_2BYTES(record->chunk->name->len, p);
  memcpy(p, record->chunk->name->data, record->chunk->name->len);
  p += record->chunk->name->len;

  if (record->op == FILE_STORE)
  {
    //printf("FILE_STORE chunk path: %s\n", record->chunk->name->data);
    if (record->data)
    {
      EDGE_LOG("data to be stored: %d", record->data->len);
      VAR_TO_PTR_2BYTES(record->data->len, p);
      memcpy(p, record->data->data, record->data->len);
    }
    else
    {
      return TEE_ERROR_BAD_STATE;
    }
    cctx->alen = 2 + record->chunk->name->len + 2 + record->data->len;
  }
  else if (record->op == FILE_LOAD)
  {
    //printf("FILE_LOAD chunk path: %s\n", record->chunk->name->data);
    //EDGE_PRINT("file path to be fetched", record->chunk->name->data, 0, 
    //    record->chunk->name->len, 10);
    cctx->alen = 2 + record->chunk->name->len;
  }

  EDGE_MSG("Finished: set_file_cctx");

  return TEE_SUCCESS;
}

/**
 * @brief Get the file command into the command context
 * @param cctx the command context
 * @param finfo the information about the file
 */
TEE_Result get_file_cctx(struct cmd_st *cctx, struct finfo *finfo, int op)
{
  EDGE_MSG("Started: get_file_cctx");
  EDGE_LOG("cctx: %p, finfo: %p", cctx, finfo);

  uint8_t *p;
  uint16_t len;

  p = cctx->arg;
  PTR_TO_VAR_2BYTES(p, len);
  init_buf_mem(&(finfo->path), p, len);
  //EDGE_PRINT("Path in get_file_cctx", p, 0, len, 10); 
  p += len;

  if (op == FILE_LOAD)
  {
    PTR_TO_VAR_2BYTES(p, len);
    init_buf_mem(&(finfo->data), p, len);
  }
  else if (op == FILE_STORE)
  {
    PTR_TO_VAR_2BYTES(p, len);
    init_buf_mem(&(finfo->data), NULL, len);
  }
  else
  {
    return TEE_ERROR_BAD_STATE;
  }

  EDGE_MSG("Finished: get_file_cctx");
  return TEE_SUCCESS;
}


/**
 * @brief Remove the requesters from the fetch record
 * @param record the fetch record to be processed
 * @param error code
 */
TEE_Result remove_requesters(struct fetch_record_st *record)
{
  // Leave the number of requesters. the number will be used to ACK of the
  // process
  
  EDGE_MSG("Start: remove_requesters");
  EDGE_LOG("record: %p", record);

  struct requester_st *curr, *next;

  if (record->num < 0)
    return TEE_ERROR_BAD_STATE;
  
  curr = record->ops->get(record, NULL);
  if (curr)
  {
    do {
      next = curr->next;
      record->ops->del(record, curr);
      record->ops->free(curr);
      if (next)
        curr = next;
      else
        break;
    } while (1);
  }
  record->num = 0;

  EDGE_MSG("Finished: remove_requester");

  return TEE_SUCCESS;
}

/**
 * @brief Add the fetch record into the queue
 * @param broker the fetch broker
 * @param record the fetch record to be inserted
 * @param queue the queue number (0: wait queue, 1: process queue, 2: finished
 * queue)
 * @return error code
 */
static TEE_Result add_record_to_queue(struct fetch_broker_st *broker, 
    struct fetch_record_st *record, int queue)
{
  EDGE_MSG("Start: add_record_to_queue");
  EDGE_LOG("broker: %p, record: %p, queue: %d", broker, record, queue);

  struct fetch_record_st *curr;

  if (queue < FINISHED_QUEUE)
  {
    while (broker->lock[queue]) {}
    broker->lock[queue] = 1;
  }

  if (broker->num[queue] == 0)
  {
    broker->queue[queue] = record;
    record->prev = NULL;
    record->next = NULL;
  }
  else
  {
    curr = broker->queue[queue];
    while (curr->next)
    {
      curr = curr->next;
    }
    curr->next = record;
    record->prev = curr;
  }
  
  broker->num[queue]++;

  if (queue < FINISHED_QUEUE)
    broker->lock[queue] = 0;

  if (queue == FINISHED_QUEUE)
    remove_requesters(record);

  EDGE_MSG("Finished: add_record_to_queue");
  return TEE_SUCCESS;
}

/**
 * @brief Delete record from the queue
 * @param broker the fetch broker
 * @param record the record to be deleted from the queue
 * @param queue the queue number (0: wait queue, 1: process queue, 2: finished
 * queue)
 * @return error code
 */
static TEE_Result del_record_from_queue(struct fetch_broker_st *broker,
    struct fetch_record_st *record, int queue)
{
  EDGE_LOG("Del Record from Queue: broker: %p, record: %p, queue: %d", broker, record, queue);
  struct fetch_record_st *curr;

  if (broker->num[queue] <= 0)
    return TEE_ERROR_BAD_STATE;

  if (queue < FINISHED_QUEUE)
  {
    EDGE_LOG("Before lock[%d]: %d", queue, broker->lock[queue]);
    while (broker->lock[queue]) {}
    broker->lock[queue] = 1;
  }

  EDGE_LOG("broker->queue[%d]: %p", queue, broker->queue[queue]);
  curr = broker->queue[queue];
  EDGE_LOG("curr: %p, record: %p", curr, record);

  do {
    if (curr == record)
      break;
    curr = curr->next;
  } while (curr);

  if (!curr)
    return TEE_ERROR_BAD_STATE;

  EDGE_MSG("Delete the record from the queue");

  if (curr->prev)
    curr->prev->next = record->next;
  else // if the record to be deleted is the first element
    broker->queue[queue] = record->next;

  if (curr->next)
  {
      curr->next->prev = record->prev;
  }

  broker->num[queue]--;

  if (broker->num[queue] == 0)
    broker->queue[queue] = NULL;

  if (queue < FINISHED_QUEUE)
  {
    broker->lock[queue] = 0;
  }

  return TEE_SUCCESS;
}

/**
 * @brief Sent the response to the requesters
 * @param broker the fetch broker
 * @param io the I/O module
 * @param cctx the command context
 * @return error code
 */
TEE_Result send_response(struct fetch_broker_st *broker, struct io_status_st *io,
    struct cmd_st *cctx)
{
  EDGE_LOG("Start: send_response: broker: %p, io: %p, cctx: %p", broker, io, cctx);

  struct fetch_record_st *record;
  struct requester_st *req;

  record = broker->ops->get_by_rinfo(broker, io->rinfo, PROGRESS_QUEUE);
  if (record->num <= 0)
    return TEE_ERROR_BAD_STATE;

  req = record->head;
  do {
      //RECORD_LOG(SSL_get_time_log(req), SERVER_SERVE_HTML_START);
    EDGE_LOG("before send response");
    io->ops->send_response(io, req->sctx);

    if (io->last >= io->size)
      req->sctx->status->finished = 1;

    EDGE_LOG("after send response");
  } while (req = req->next);

  broker->mngr->vops->store(broker->mngr, io);

  if (io->last >= io->size)
  {
    EDGE_LOG("Finished to send the response");
    broker->ops->finished(broker, record, FINISHED_QUEUE);
    io->finished = 1;
  }

  EDGE_MSG("Finished: send_response");
  return TEE_SUCCESS;
}

/**
 * @brief Process the load command
 * @param cctx the command context
 * @return error code
 */
TEE_Result process_cmd_load(struct fetch_broker_st *broker, struct cmd_st *cctx)
{
  EDGE_MSG("Start: process_cmd_load");
  EDGE_LOG("broker: %p, cctx: %p, cctx->alen: %d", broker, cctx, cctx->alen);

  struct finfo finfo;
  struct fetch_record_st *record;
  struct requester_st *curr;
  struct buf_st *ciph, *plain;
  struct chunk_st *chunk;
  uint8_t *p;
  uint32_t seq, dlen, plen;
  int sent;
#ifdef TIME_LOG
  log_t *time_log;
  time_log = broker->time_log;
#endif /* TIME_LOG */

  RECORD_LOG(broker->time_log, LOG_13);
  get_file_cctx(cctx, &finfo, FILE_LOAD);
  RECORD_LOG(broker->time_log, LOG_14);

  EDGE_LOG("Before get_fetch_record_from_queue_by_path: %s", qname[PROGRESS_FILE_QUEUE]);
  //PRINT_QUEUE(PROGRESS_FILE_QUEUE);
  RECORD_LOG(broker->time_log, LOG_15);
  record = get_fetch_record_from_queue_by_path(broker, finfo.path, PROGRESS_FILE_QUEUE, NULL, 
      FILE_LOAD);
  RECORD_LOG(broker->time_log, LOG_16);
  EDGE_LOG("After get_fetch_record_from_queue_by_path: %s", qname[PROGRESS_FILE_QUEUE]);
  //PRINT_QUEUE(PROGRESS_FILE_QUEUE);
  EDGE_LOG("Found Record: %p", record);

  if (!record)
    return TEE_ERROR_BAD_STATE;

  RECORD_LOG(broker->time_log, LOG_17);
  chunk = record->chunk;
  ciph = finfo.data;
  RECORD_LOG(broker->time_log, LOG_18);
  plain = init_alloc_buf_mem(&plain, BUF_SIZE);

#ifndef NO_SEALING
  broker->mngr->key->ops->decrypt(broker->mngr->key, record->cinfo->salt->data, 
      record->cinfo->salt->len, ciph->data, ciph->len, plain->data, &(plain->len));

  RECORD_LOG(broker->time_log, LOG_19);
  EDGE_LOG("Decrypted file: %s", plain->data);
#else
  plain->len = ciph->len;
  memcpy(plain->data, ciph->data, plain->len);
#endif /* NO_SEALING */

  EDGE_LOG("Record in the loop: %p", record);
  // Should not be happened
  if (record->num <= 0)
    return TEE_ERROR_BAD_STATE;

  curr = record->head;
  EDGE_LOG("curr: %p", curr);

  RECORD_LOG(broker->time_log, LOG_20);
  
  while (curr)
  {
    if (curr->sctx && curr->sctx->ssl)
    {
      sent = SSL_write(curr->sctx->ssl, plain->data, plain->len);
    }

    if (curr->next)
      curr = curr->next;
    else
      break;
  }

  RECORD_LOG(broker->time_log, LOG_21);

  if (record->chunk->next)
  {
    record->chunk = record->chunk->next;

    /////
    set_file_cctx(cctx, record);
    cctx->flags = TA_EDGE_CACHE_NXT_LOAD;
    /////
    //next_chunk(broker, record, WAIT_FILE_QUEUE);
  }
  else
  {
    broker->ops->finished(broker, record, FINISHED_FILE_QUEUE);
    /////
    cctx->flags = TA_EDGE_CACHE_NXT_POLL_IO;
    /////
  }

  RECORD_LOG(broker->time_log, LOG_22);

  //cctx->flags = TA_EDGE_CACHE_NXT_POLL_IO;
  free_buf(plain);

  EDGE_MSG("Finished: process_cmd_load");
  return TEE_SUCCESS;
}

/**
 * @brief Process the store command
 * @param cctx the command context
 * @return error code
 */
TEE_Result process_cmd_store(struct fetch_broker_st *broker, struct cmd_st *cctx)
{
  EDGE_MSG("Start: process_cmd_store");
  EDGE_LOG("broker: %p, cctx: %p", broker, cctx);

  struct finfo finfo;
  struct fetch_record_st *record;

  get_file_cctx(cctx, &finfo, FILE_STORE);

  record = get_fetch_record_from_queue_by_path(broker, finfo.path, PROGRESS_FILE_QUEUE, NULL, 
      FILE_STORE);

  // TODO: Is there next chunk? It should be considered to deal with the
  // fragmentation
  //PRINT_QUEUE(PROGRESS_FILE_QUEUE);
  del_record_from_queue(broker, record, PROGRESS_FILE_QUEUE);
  //PRINT_QUEUE(PROGRESS_FILE_QUEUE);

  cctx->flags = TA_EDGE_CACHE_NXT_POLL_IO;

  EDGE_MSG("Finished: process_cmd_store");
  return TEE_SUCCESS;
}

static struct fetch_broker_ops ops =
{
  .get_by_name = get_fetch_record_from_queue_by_name,
  .get_by_rinfo = get_fetch_record_from_queue_by_rinfo,
  .remove_by_rinfo = remove_fetch_record_from_queue_by_rinfo,
  .push_into_queue = push_into_queue,
  .finished = finished,
  .check_finished = check_finished,
  .poll_request = poll_request,
  .send_response = send_response,
  .process_cmd_load = process_cmd_load,
  .process_cmd_store = process_cmd_store
};

/**
 * @brief Initialize the fetch broker
 * @param broker the pointer to the broker to be initialized
 * @param front the pointer to the frontend TLS manager
 * @param back the pointer to the backend TLS manager
 * @param mngr the pointer to the file manager
 * @return error code
 */
TEE_Result init_fetch_broker(struct fetch_broker_st **broker, struct tls_manager_st *front,
    struct tls_manager_st *back, struct file_manager_st *mngr, void *time_log)
{
  int i;
  (*broker) = (struct fetch_broker_st *)malloc(sizeof(struct fetch_broker_st));
  memset((*broker), 0x0, sizeof(struct fetch_broker_st));
  front->broker = *broker;
  back->broker = *broker;
  mngr->broker = *broker;
  (*broker)->mngr = mngr;

  for (i=0; i<NUM_OF_QUEUES; i++)
    (*broker)->num[i] = 0;

  for (i=0; i<NUM_OF_QUEUES; i++)
    (*broker)->lock[i] = 0;

  (*broker)->ops = &ops;

  for (i=0; i<NUM_OF_QUEUES; i++)
    (*broker)->queue[i] = NULL;

  if (time_log)
    (*broker)->time_log = (log_t *)time_log;

  return TEE_SUCCESS;
}
