#include "ta_debug.h"

void init_commands(void)
{
  commands[TA_EDGE_CACHE_CMD_INIT]          = "TA_EDGE_CACHE_CMD_INIT",
  commands[TA_EDGE_CACHE_CMD_TLS]           = "TA_EDGE_CACHE_CMD_TLS";
  commands[TA_EDGE_CACHE_CMD_SHUTDOWN]      = "TA_EDGE_CACHE_CMD_SHUTDOWN";

  commands[TA_EDGE_CACHE_CMD_GET_DOMAIN]    = "TA_EDGE_CACHE_CMD_GET_DOMAIN";
  commands[TA_EDGE_CACHE_CMD_GET_CC]        = "TA_EDGE_CACHE_CMD_GET_CC";
  commands[TA_EDGE_CACHE_CMD_GET_DATA_INIT] = "TA_EDGE_CACHE_CMD_GET_DATA_INIT";
  commands[TA_EDGE_CACHE_CMD_GET_DATA]      = "TA_EDGE_CACHE_CMD_GET_DATA";

  commands[TA_EDGE_CACHE_CMD_POLL_FETCH]    = "TA_EDGE_CACHE_CMD_POLL_FETCH";
  commands[TA_EDGE_CACHE_CMD_POLL_DATA]     = "TA_EDGE_CACHE_CMD_POLL_DATA";
  commands[TA_EDGE_CACHE_CMD_POLL_IO]     = "TA_EDGE_CACHE_CMD_POLL_IO";

  commands[TA_EDGE_CACHE_CMD_LOAD]          = "TA_EDGE_CACHE_CMD_LOAD";
  commands[TA_EDGE_CACHE_CMD_STORE]         = "TA_EDGE_CACHE_CMD_STORE";

  commands[TA_EDGE_CACHE_NXT_EXIT]          = "TA_EDGE_CACHE_NXT_EXIT";
  commands[TA_EDGE_CACHE_CMD_TEST]          = "TA_EDGE_CACHE_CMD_TEST";
}

char *cmd_to_str(int num)
{
  return commands[num];
}

