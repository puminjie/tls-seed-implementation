#ifndef __CMDS_H__
#define __CMDS_H__

/* TLS related operation (NW to SW) */

#define TA_EDGE_CMD_INIT            0
// initialize the managers of the EC.

#ifndef TA_EDGE_CMD_TLS
#define TA_EDGE_CMD_TLS             1 
#endif /* TA_EDGE_CMD_TLS */
// execute the TLS operation

#define TA_EDGE_CMD_FINISH          2
// shutdown the TLS context

#define TA_EDGE_CMD_GET_DOMAIN      3 
// load the domain list from the trusted (platform) authority 

#define TA_EDGE_CMD_GET_CC          4  
// get the CC from the origins

#define TA_EDGE_CMD_GET_DATA_INIT   5
#define TA_EDGE_CMD_GET_DATA        6 
// fetch the data from the origins

#define TA_EDGE_CMD_POLL_FETCH      7
// check whether there is any request for fetching

#define TA_EDGE_CMD_POLL_DATA       8
// check whether the data fetching is finished

#define TA_EDGE_CMD_POLL_IO         9
// check whether the file I/O is requested

#define TA_EDGE_CMD_LOAD            10
// file load operation

#define TA_EDGE_CMD_STORE           11
// file store operation

#define TA_EDGE_CMD_TEST            12 // test command
// test the primitive operations

#define TA_EDGE_CMD_FALLBACK_INIT   13
#define TA_EDGE_CMD_FALLBACK_FRONT  14
#define TA_EDGE_CMD_FALLBACK_BACK   15

#ifndef TA_EDGE_CMD_TLS_INIT
  #define TA_EDGE_CMD_TLS_INIT      16
#endif /* TA_EDGE_CMD_TLS_INIT */

#ifndef TA_EDGE_CMD_TLS_FINISH
  #define TA_EDGE_CMD_TLS_FINISH    17
#endif /* TA_EDGE_CMD_TLS_FINISH */

/* Direction to the host application forwarder */
#define TA_EDGE_NXT_TLS             TA_EDGE_CMD_TLS
// arg: none, alen: 0

#define TA_EDGE_NXT_LOAD            TA_EDGE_CMD_LOAD
// arg: last bytes (4 bytes), length of path (2 bytes), file path, 
// alen: length of the file path + 6

#define TA_EDGE_NXT_STORE           TA_EDGE_CMD_STORE
// arg: last bytes (4 bytes, 0000), length of path (2 bytes), file path, sealed file, 
// alen: length of the file and the file path + 6

#define TA_EDGE_NXT_GET_DOMAIN      TA_EDGE_CMD_GET_DOMAIN
// arg: address info, alen: length of the address info

#define TA_EDGE_NXT_GET_CC          TA_EDGE_CMD_GET_CC
// arg: address info, alen: length of the address info

#define TA_EDGE_NXT_GET_DATA_INIT   TA_EDGE_CMD_GET_DATA_INIT
// arg: address info, alen: length of the address info

#define TA_EDGE_NXT_GET_DATA        TA_EDGE_CMD_GET_DATA
// arg: address info, alen: length of the address info

#define TA_EDGE_NXT_POLL_DATA       TA_EDGE_CMD_POLL_DATA

#define TA_EDGE_NXT_POLL_FETCH      TA_EDGE_CMD_POLL_FETCH

#define TA_EDGE_NXT_POLL_IO         TA_EDGE_CMD_POLL_IO

#define TA_EDGE_NXT_EXIT            127
// arg: none, alen: 0

#define TA_EDGE_NXT_FALLBACK_INIT   TA_EDGE_CMD_FALLBACK_INIT
// arg: address info, client hello, alen: length of data

#define TA_EDGE_NXT_FALLBACK_FRONT  TA_EDGE_CMD_FALLBACK_FRONT
#define TA_EDGE_NXT_FALLBACK_BACK   TA_EDGE_CMD_FALLBACK_BACK

// Init setting for the command context
#define TA_EDGE_INIT_INITIALIZER  TA_EDGE_CMD_INIT
#define TA_EDGE_INIT_FRONTEND     TA_EDGE_CMD_TLS_INIT
#define TA_EDGE_INIT_BACKEND      TA_EDGE_CMD_POLL_FETCH
#define TA_EDGE_INIT_FILE_IO      TA_EDGE_CMD_POLL_IO

// Stages
#define TA_EDGE_GET_DOMAIN_INIT           0
#define TA_EDGE_GET_DOMAIN_REQUEST_SENT   1
#define TA_EDGE_GET_DOMAIN_RESPONSE_RCVD  2

#define TA_EDGE_GET_CC_INIT               0
#define TA_EDGE_GET_CC_ONGOING            1
#define TA_EDGE_GET_CC_REQUEST_SENT       2
#define TA_EDGE_GET_CC_RESPONSE_RCVD      3

#define TA_EDGE_GET_DATA_INIT             0
#define TA_EDGE_GET_DATA_NEXT             1
#define TA_EDGE_GET_DATA_FINISH           2

#endif /* __CMDS_H__ */
