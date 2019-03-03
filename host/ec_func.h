#ifndef __EC_FUNC_H__
#define __EC_FUNC_H__

#include <stdio.h>
#include <resolv.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>

#include "edge_cache.h"
#include "hio.h"
#include "file_io_manager.h"
//#include "log_client.h"

#include <tee_client_api.h>
#include <ta_edge_cache.h>

#define MAX_HOST_LEN  256

// I/O related functions
TEEC_Result forward_tls_messages(struct ec_ctx *ctx, TEEC_Operation *op);
TEEC_Result client_operation(struct ec_ctx *ctx, struct hiom_st *iom, TEEC_Operation *op, 
    uint8_t flag, int role);
TEEC_Result notify_closed_to_secure_world(struct ec_ctx *ctx, TEEC_Operation *op);
//void horizontal_operation(struct forwarder_st *sock[]);
void horizontal_operation(struct forwarder_st *sock[], struct file_io_manager_st *mngr);
void vertical_operation(struct forwarder_st *sock[]);

int open_connection(char *name, uint16_t port, TEEC_Operation *op);
TEEC_Result communicate_with_secure_world(struct ec_ctx *ctx, TEEC_Operation *op, uint8_t flag,
    int role);

#endif /* __EC_FUNC_H__ */
