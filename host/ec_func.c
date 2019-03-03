#include "ec_func.h"
#include "debug.h"

TEEC_Result get_address(uint8_t *buf, uint32_t len, uint8_t *host, uint16_t *port);

TEEC_Result forward_tls_messages(struct ec_ctx *ctx, TEEC_Operation *op)
{
  EDGE_MSG("forward_tls_messages start");
  TEEC_Result res;
  uint32_t origin;

  res = TEEC_InvokeCommand(&ctx->sess, TA_EDGE_CACHE_CMD_TLS, op, &origin);

  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_InvokeCommand Test failed 0x%x origin 0x%x", res, origin);

  EDGE_MSG("forward_tls_messages finish");
  return res;
}

/**
 * @brief Get the order from the secure world
 * @param ctx Context of EC
 * @param op TEEC_Operation
 * @param flag Types of operation
 * @return Error code
 */
TEEC_Result communicate_with_secure_world(struct ec_ctx *ctx, TEEC_Operation *op, uint8_t flag,
    int role)
{
  TEEC_Result res;
  uint32_t origin;
  int communicate;
  communicate = 0;

  EDGE_LOG("Flag in communicate_with_secure_world (%d): %s", role, cmd_to_str(flag));

  switch(flag)
  {
    case TA_EDGE_CACHE_CMD_INIT:
    case TA_EDGE_CACHE_CMD_TLS:
    case TA_EDGE_CACHE_CMD_SHUTDOWN:
    case TA_EDGE_CACHE_CMD_GET_DOMAIN:
    case TA_EDGE_CACHE_CMD_GET_CC:
    case TA_EDGE_CACHE_CMD_GET_DATA_INIT:
    case TA_EDGE_CACHE_CMD_GET_DATA:
    case TA_EDGE_CACHE_CMD_LOAD:
    case TA_EDGE_CACHE_CMD_STORE:
    case TA_EDGE_CACHE_CMD_POLL_FETCH:
    case TA_EDGE_CACHE_CMD_POLL_DATA:
    case TA_EDGE_CACHE_CMD_POLL_IO:
    case TA_EDGE_CACHE_CMD_TEST:
      communicate = 1;
      break;
    default:
      EDGE_MSG("Nothing is assigned as Command");
  }

  if (communicate)
  {
    //EDGE_LOG("========== role: %d, &ctx->sess: %p, cmd: %s, op: %p ==========", role, 
    //    &ctx->sess, cmd_to_str(flag), op);
    res = TEEC_InvokeCommand(&ctx->sess, flag, op, &origin);
    //EDGE_LOG("========== cmd: %s, res: %d ==========", cmd_to_str(flag), res);
  }
  EDGE_MSG("");

  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_InvokeCommand Test failed 0x%x origin 0x%x", res, origin);

  return res;
}

/**
 * @brief Notify the client's close message to the secure world
 * @param ctx Context of EC
 * @param op TEEC_Operation
 * @return Error code
 */
TEEC_Result notify_closed_to_secure_world(struct ec_ctx *ctx, TEEC_Operation *op)
{
  TEEC_Result res;
  uint32_t origin;

  res = communicate_with_secure_world(ctx, op, TA_EDGE_CACHE_CMD_SHUTDOWN, &origin);

  return res;
}

/**
 * @brief Get the IP address and the port
 * @param buf the buffer involving the address and the port
 * @param len the length of the buffer
 * @param host the hostname to be assigned
 * @param port the port to be assigned
 * @return Error code
 */
TEEC_Result get_address(uint8_t *buf, uint32_t len, uint8_t *host, uint16_t *port)
{
  // hostname length (1 byte) || hostname || port (2 bytes)
  uint8_t hlen;
  uint8_t *p;

  p = buf;
  hlen = (*p++);
  memcpy(host, p, hlen);
  host[hlen] = 0;
  p += hlen;
  *port = ((p[0]) << 8) | (p[1]);

  EDGE_LOG("Address: %s / Port: %d", host, *port);

  return TEEC_SUCCESS;
}

/**
 * @brief Basic networking module as a client
 * @param ctx Context of EC
 * @param iom I/O module
 * @param op TEEC_Operation
 * @return Error code
 */
TEEC_Result client_operation(struct ec_ctx *ctx, struct hiom_st *iom, TEEC_Operation *op, 
    uint8_t flag, int role)
{
  TEEC_Result res;
  int32_t sd, sent, recv;
  struct cmd_st *cmd;
  struct sockaddr_in local;
  uint8_t rbuf[BUF_SIZE], wbuf[BUF_SIZE];
  uint8_t host[MAX_HOST_LEN];
  uint16_t port;
  socklen_t len;

  res = TEEC_SUCCESS;
  cmd = get_cmd_ctx(iom);
  cmd->flags = flag;
  get_address(cmd->arg, cmd->alen, host, &port);
  sd = open_connection(host, port, op);

  memset(&local, 0x0, sizeof(local));
  len = sizeof(local);
  getsockname(sd, (struct sockaddr *)&local, &len);
  EDGE_LOGinfo(local.sin_addr.s_addr, local.sin_port);
  set_client(iom, (uint32_t) local.sin_addr.s_addr, (uint16_t) ntohs(local.sin_port));

  while (1)
  {
    communicate_with_secure_world(ctx, op, flag, role);
    EDGE_MSG("After communicate with secure world");
    if ((recv = read(sd, rbuf, BUF_SIZE)) >= 0)
    {
      if (recv == 0)
      {
        EDGE_LOG("Socket is closed by peer");
        break;
      }
      EDGE_LOG("Received messages from the outside: %d", recv);
      recv = forward_to_secure_world(iom, rbuf, recv);
      EDGE_LOG("Forward messages to the secure world: %d", recv);
    }

    if ((sent = forward_to_out_world(iom, wbuf, BUF_SIZE)) > 0)
    {
      EDGE_LOG("Messages to be sent from the secure world: %d", sent);
      sent = write(sd, wbuf, sent);
      EDGE_LOG("Message sent: %d", sent);
    }

    if (cmd->flags != flag)
    {
      EDGE_LOG("Now close the session with the authority");
      break;
    }
  }

  close(sd);
  return res;
}

/**
 * @brief Open the connection with the authority
 * @return The client's socket descriptor
 */
int open_connection(char *name, uint16_t port, TEEC_Operation *op)
{
  int sd, option;
  struct hostent *host;
  struct sockaddr_in addr;
  option = 1;
#ifdef TIME_LOG
  log_t *time_log;
  time_log = get_time_log(op);
#endif /* TIME_LOG */

  if ((host = gethostbyname(name)) == NULL)
  {
    EDGE_LOG("gethostbyname() error");
  }

  sd = socket(PF_INET, SOCK_STREAM, 0);
  setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
  if (sd < 0)
    EDGE_LOG("client socket() error");
  else
    EDGE_LOG("client socket() success");
  
  memset(&addr, 0x0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long *)(host->h_addr);

  RECORD_LOG(time_log, CLIENT_TCP_START);
  if (connect(sd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    close(sd);
    abort();
    return -1;
  }
  RECORD_LOG(time_log, CLIENT_TCP_END);
  fcntl(sd, F_SETFL, O_NONBLOCK);
  EDGE_LOG("connect to %s:%d succeed", name, port);

  return sd;
}

