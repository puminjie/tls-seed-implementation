/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/ec.h>

/* OP-TEE TEE clnt API */
#include <tee_client_api.h>

/* UUID */
#include <ta_edge_cache.h>

#include "host_defines.h"
#include "edge_cache.h"
#include "ec_func.h"
#include "init.h"
//#include "log_client.h"
#include "debug.h"
#include "hio.h"
#include "file_io_manager.h"

pthread_t threads[MAX_THREADS];
pthread_attr_t attr;
int get_thread_index();
void *status;
void *main_loop(void *data);
struct file_io_manager_st *mngr;
void read_operation(struct ec_sock *sock[]);
void write_operation(struct ec_sock *sock[]);
void horizontal_operation(struct ec_sock *sock[]);

int main(int argc, char *argv[])
{
  uint32_t i;
  struct ec_ctx ctx;
#ifdef TIME_LOG
  uint64_t tcp_start, tcp_end;
  uint8_t *type;
  uint32_t exp_no;
  uint32_t sequence;
  uint8_t log_dir[MAX_FILE_NAME_LEN];
  uint8_t init_log_file_name[MAX_FILE_NAME_LEN];
  uint8_t ec_log_file_name[MAX_FILE_NAME_LEN];
  struct stat st = {0};
#endif /* TIME_LOG */

  // Declaration for server app.
  int edge, clnt, tidx, rc;
  struct sockaddr_in ec_addr, clnt_addr;
  socklen_t clnt_addr_size;

#ifdef TIME_LOG
  // Time log buffer.
  log_t init_log[NUM_OF_LOGS];
  INITIALIZE_LOG(init_log);
#endif /* TIME_LOG */

#ifndef TIME_LOG
  if (argc != 2)
  {
    fprintf(stderr, "Usage: %s <port>\n", argv[0]);
    exit(1);
  }
#else
  if (argc != 5)
  {
    fprintf(stderr, "Usage: %s <port> <type> <exp no.> <sequence>\n", argv[0]);
    exit(1);
  }

  type = argv[2];
  exp_no = atoi(argv[3]);
  sequence = atoi(argv[4]);
  memset(init_log_file_name, 0x0, sizeof(init_log_file_name));
  memset(ec_log_file_name, 0x0, sizeof(ec_log_file_name));

  if (stat(DEFAULT_LOG_DIRECTORY, &st) < 0)
  {
    mkdir(DEFAULT_LOG_DIRECTORY, 0755);
  }

  snprintf(log_dir, MAX_FILE_NAME_LEN, "%s/%d", DEFAULT_LOG_DIRECTORY, exp_no);

  if (stat(log_dir, &st) < 0)
  {
    mkdir(log_dir, 0755);
  }

  snprintf(init_log_file_name, MAX_FILE_NAME_LEN, "%s/%d/%s_init_%d.csv", 
      DEFAULT_LOG_DIRECTORY, exp_no, type, sequence);
  snprintf(ec_log_file_name, MAX_FILE_NAME_LEN, "%s/%d/%s_%d.csv", 
      DEFAULT_LOG_DIRECTORY, exp_no, type, sequence);
#endif /* TIME_LOG */

  edge = socket(PF_INET, SOCK_STREAM, 0);
  if (edge < 0)
    perror("edge) socket() error");
  EDGE_LOG("socket() success");

  fcntl(edge, F_SETFL, O_NONBLOCK);

  memset(&ec_addr, 0, sizeof(ec_addr));
  memset(&clnt_addr, 0, sizeof(clnt_addr));
  ec_addr.sin_family = AF_INET;
  ec_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  ec_addr.sin_port = htons(atoi(argv[1]));

  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

  if (bind(edge, (struct sockaddr *)&ec_addr, sizeof(ec_addr)) < 0)
    perror("edge) bind() error");
  EDGE_LOG("bind() success");
  
  if (listen(edge, MAX_THREADS) < 0)
    perror("listen() error");
  EDGE_LOG("listen() success");

  EDGE_LOG("prepare session with the TA");
  prepare_tee_session(&ctx);

#ifdef TIME_LOG
  init(&ctx, init_log);
#else
  init(&ctx, NULL);
#endif /* TIME_LOG */

  init_file_io_manager(&mngr);

#ifdef TIME_LOG
  PRINT_LOG(init_log);
  EDGE_LOG("Init Log File Name: %s", init_log_file_name);
  FINALIZE(init_log, init_log_file_name);
#endif /* TIME_LOG */

  EDGE_LOG("start edge cache application: tls-ec");

  while (1)
  {
#ifdef TIME_LOG
    tcp_start = get_current_millis();
#endif /* TIME_LOG */
    clnt = accept(edge, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
    if (clnt > 0)
    {
#ifdef TIME_LOG
    tcp_end = get_current_millis();
#endif /* TIME_LOG */
      getpeername(clnt, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
      EDGE_LOGinfo(clnt_addr.sin_addr.s_addr, clnt_addr.sin_port);
      fcntl(clnt, F_SETFL, O_NONBLOCK);

      struct info *info = (struct info *)malloc(sizeof (struct info));
      info->fd = clnt;
      info->ctx = &ctx;
      info->ip = (uint32_t) clnt_addr.sin_addr.s_addr;
      info->port = (uint16_t) ntohs(clnt_addr.sin_port);
#ifdef TIME_LOG
      info->tcp_start = tcp_start;
      info->tcp_end = tcp_end;
      info->log_file_name = ec_log_file_name;
#endif /* TIME_LOG */

      tidx = get_thread_index();
      rc = pthread_create(&threads[tidx], &attr, main_loop, info);

      if (rc < 0)
      {
        EDGE_LOG("Error in pthread_create()");
        exit(1);
      }
    }
  }

  EDGE_LOG("The thread is ended");
  terminate_tee_session(&ctx);

  for (i=0; i<MAX_THREADS; i++)
  {
    rc = pthread_join(threads[i], &status);

    if (rc)
    {
      printf("error: return code from pthread_join: %d\n", rc);
      return 1;
    }
  }

  close(edge);
  EDGE_LOG("terminate edge cache application");

  return 0;
}


void *main_loop(void *data)
{
#ifdef TIME_LOG
  log_t time_log[NUM_OF_LOGS];
  INITIALIZE_LOG(time_log);
#endif
  EDGE_LOG("Start an edge cache thread");
  struct info *info;
  struct ec_sock *sock[2];

  info = (struct info *)data;
#ifdef TIME_LOG
  time_log[SERVER_TCP_START].time = info->tcp_start;
  time_log[SERVER_TCP_END].time = info->tcp_end;
  init_socket(&(sock[FRONTEND]), info->fd, info->ctx, FRONTEND, (void *)time_log);
  init_socket(&(sock[BACKEND]), -1, info->ctx, BACKEND, (void *)time_log);
#else
  init_socket(&(sock[FRONTEND]), info->fd, info->ctx, FRONTEND, NULL);
  init_socket(&(sock[BACKEND]), -1, info->ctx, BACKEND, (void *)time_log);
#endif

  RECORD_LOG(time_log, SERVER_HANDSHAKE_START);
  while (1)
  {
    read_operation(sock);
    horizontal_operation(sock);
    write_operation(sock);
    
    // TODO: Check the condition. Is this right?
    if ((sock[FRONTEND]->close) && (sock[BACKEND] && sock[BACKEND]->close))
      break;
  }

  free_socket(sock);

#ifdef TIME_LOG
  RECORD_LOG(time_log, SERVER_SERVE_HTML_END);
  EDGE_LOG("Log File Name: %s", info->log_file_name);
  FINALIZE(time_log, info->log_file_name);
#endif
  EDGE_LOG("The thread is ending");
  close(info->fd);
  free(info);

  EDGE_LOG("Before exiting the main loop function");
  return 0;
}

TEEC_Result init_socket(struct ec_sock **sk, int fd, struct ec_ctx *ctx, int role, 
    void *log)
{
  struct sockaddr_in addr;
  socklen_t addr_len;
  uint32_t ip;
  uint16_t port;

#ifdef TIME_LOG
  log_t *time_log;
  time_log = (log_t *)log;
#endif 

  (*sk) = (struct ec_sock *)malloc(sizeof(struct ec_sock));
  (*sk)->fd = fd;
  (*sk)->ctx = ctx;
  (*sk)->tctx = &(ctx->ctx);
  (*sk)->iom = NULL;
  (*sk)->close = 0;

  if (init_iom(&((*sk)->iom), (*sk)->tctx, role) < 0)
    return TEEC_ERROR_BAD_STATE;

#ifdef TIME_LOG
  set_op(&((*sk)->op), (*sk)->iom, time_log);
#else
  set_op(&((*sk)->op), (*sk)->iom, NULL);
#endif 
  
  if ((*sk)->fd > 0)
  {
    if (role == FRONTEND)
    {
      getpeername(fd, (struct sockaddr *)&addr, &addr_len);
    }
    else if (role == BACKEND)
    {
      getsockname(fd, (struct sockaddr *)&addr, &addr_len);
    }
    else
    {
      return TEEC_ERROR_BAD_PARAMETERS;
    }

    ip = addr.sin_addr.s_addr;
    port = addr.sin_port;
    EDGE_LOGinfo(ip, port);

    set_client((*sk)->iom, ip, port);
  }

  return TEEC_SUCCESS;
}

TEEC_Result prepare_socket(struct ec_sock *sk, struct cmd_st *cctx, int role)
{
  struct sockaddr_in addr;
  socklen_t addr_len;
  uint32_t ip;
  uint8_t name[MAX_HOST_LEN];
  uint16_t port, p;
  char my_ip[16];

  get_address(cctx->arg, cctx->alen, name, &p);
  sk->fd = open_connection(name, p, &(sk->op));

  memset(&addr, 0x0, sizeof(addr));
  addr_len = sizeof(addr);

  if (role == FRONTEND)
  {
    getpeername(sk->fd, (struct sockaddr *)&addr, &addr_len);
  }
  else if (role == BACKEND)
  {
    getsockname(sk->fd, (struct sockaddr *)&addr, &addr_len);
  }
  else
  {
    return TEEC_ERROR_BAD_PARAMETERS;
  }
  ip = (uint32_t) addr.sin_addr.s_addr;
  port = (uint16_t) addr.sin_port;

  EDGE_LOGinfo(ip, port);

  set_client(sk->iom, ip, port);

  return TEEC_SUCCESS;
}


void free_socket(struct ec_sock *sock[])
{
  uint8_t i;
  struct ec_sock *sk;
  for (i=0; i<2; i++)
  {
    sk = sock[i];
    if (!sk)
      continue;

    free_iom(sk->iom, sk->tctx);
    close(sk->fd);
  }
}

int get_thread_index(void)
{
  int i, ret = -1;

  for (i=0; i<MAX_THREADS; i++)
    if (!threads[i])
    {
      ret = i;
      break;
    }

  return ret;
}

void read_operation(struct ec_sock *sock[])
{
  EDGE_MSG("Vertical Operation Start");
  int8_t i;
  int32_t recv, sent;
  struct ec_sock *sk;

  for (i=0; i<2; i++)
  {
    sk = sock[i];

    if (!sk)
      continue;

    EDGE_LOG("Before Read Operation by sock[%d]", i);
    if ((recv = read(sk->fd, sk->rbuf, BUF_SIZE)) > 0)
    {
      EDGE_LOG("===== Received messages from the sock[%d]: %d", i, recv);
      if (recv == 0)
      {
        EDGE_LOG("The clnt closed the socket");
        notify_closed_to_secure_world(sk->ctx, &(sk->op));
        sk->close = 1;
      }
      recv = forward_to_secure_world(sk->iom, sk->rbuf, recv);
      EDGE_LOG("Forward messages to the secure world: %d", recv);
      EDGE_LOG("Invoke forward_messages()");
      //forward_tls_messages(sk->ctx, &(sk->op));
      EDGE_LOG("forward_messages() finished");
    }
    EDGE_LOG("After Read Operation by sock[%d]", i);
  }
}

void write_operation(struct ec_sock *sock[])
{
  EDGE_MSG("Vertical Operation Start");
  int8_t i;
  int32_t recv, sent;
  struct ec_sock *sk;

  for (i=0; i<2; i++)
  {
    EDGE_LOG("Before Write Operation by sock[%d]", i);
    sk = sock[i];

    if (!sk)
      continue;

    if ((sent = forward_to_out_world(sk->iom, sk->wbuf, BUF_SIZE)) > 0)
    {
      EDGE_LOG("===== Messages to be sent from the secure world: %d", sent);
      sent = write(sk->fd, sk->wbuf, sent);
    }
    EDGE_LOG("After Write Operation by sock[%d]", i);
  }
  EDGE_MSG("Vertical Operation Finish");
}

void frontend_operation(struct ec_sock *sk)
{
  EDGE_MSG("Front End Operation Start");
  uint8_t communicate;
  struct cmd_st *cctx;
  struct finfo finfo;
  
  communicate = 0;
  cctx = get_cmd_ctx(sk->iom);

  EDGE_LOG("Flags in frontend operation: %s", cmd_to_str(cctx->flags));
  switch (cctx->flags)
  {
    case TA_EDGE_CACHE_NXT_TLS:
      communicate = 1;
      EDGE_MSG("Execute TLS Handshake");
      break;

    case TA_EDGE_CACHE_NXT_LOAD:
      change_to_file_info(&finfo, cctx);
      EDGE_LOG("Load the content from %s", finfo.path);
      mngr->ops->load(&finfo, cctx);
      communicate = 1;
      break;

    case TA_EDGE_CACHE_NXT_STORE:
      EDGE_MSG("Store the content");
      change_to_file_info(&finfo, cctx);
      EDGE_LOG("Store the content to %s", finfo.path);
      mngr->ops->store(&finfo, cctx);
      communicate = 1;
      break;
    
    case TA_EDGE_CACHE_NXT_POLL_DATA:
      EDGE_MSG("Poll data");
      communicate = 1;
      break;

    case TA_EDGE_CACHE_NXT_EXIT:
      EDGE_MSG("Exit loop");
      sk->close = 1;
      break;
  }
    
  if (communicate)
  {
    EDGE_LOG("========== frontend: sk->ctx: %p, &(sk->op): %p, cctx->flags: %s ==========",
        sk->ctx, &(sk->op), cmd_to_str(cctx->flags));
    communicate_with_secure_world(sk->ctx, &(sk->op), cctx->flags, FRONTEND);
  }

  EDGE_MSG("Front Operation Finish");
}

void backend_operation(struct ec_sock *sk)
{
  EDGE_MSG("Backend Operation Start");
  uint8_t communicate;
  struct cmd_st *cctx;
  communicate = 0;
  cctx = get_cmd_ctx(sk->iom);

  EDGE_LOG("Flags in backend operation: %s", cmd_to_str(cctx->flags));
  switch(cctx->flags)
  {
    case TA_EDGE_CACHE_NXT_TLS:
      communicate = 1;
      break;

    case TA_EDGE_CACHE_NXT_GET_DATA_INIT:
      EDGE_MSG("Fetch init. Prepare the socket for the backend");
      prepare_socket(sk, cctx, BACKEND);
      EDGE_MSG("Fetch init complete");
      communicate = 1;
      break;

    case TA_EDGE_CACHE_NXT_GET_DATA:
      EDGE_MSG("Fetch progressing");
      communicate = 1;
      break;

    case TA_EDGE_CACHE_NXT_POLL_FETCH:
      EDGE_MSG("Polling the fetch request");
      communicate = 1;
      break;

    case TA_EDGE_CACHE_NXT_EXIT:
      EDGE_MSG("Exit loop");
      sk->close = 1;
      break;

    default:
      EDGE_MSG("Default is doing nothing");
  }

  if (communicate)
  {
    EDGE_LOG("========== backend: sk->ctx: %p, &(sk->op): %p, cctx->flags: %s ==========",
        sk->ctx, &(sk->op), cmd_to_str(cctx->flags));
    communicate_with_secure_world(sk->ctx, &(sk->op), cctx->flags, BACKEND);
  }
  EDGE_MSG("Backend Operation Finish");
}

void horizontal_operation(struct ec_sock *sock[])
{
  frontend_operation(sock[FRONTEND]);
  backend_operation(sock[BACKEND]);
}
