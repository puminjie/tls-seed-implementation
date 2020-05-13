#include "ta_debug.h"

void init_commands(void)
{
  efstart();
  commands[TA_EDGE_CMD_INIT]          = "TA_EDGE_CMD_INIT",
  commands[TA_EDGE_CMD_TLS]           = "TA_EDGE_CMD_TLS";
  commands[TA_EDGE_CMD_FINISH]        = "TA_EDGE_CMD_SHUTDOWN";

  commands[TA_EDGE_CMD_GET_DOMAIN]    = "TA_EDGE_CMD_GET_DOMAIN";
  commands[TA_EDGE_CMD_GET_CC]        = "TA_EDGE_CMD_GET_CC";
  commands[TA_EDGE_CMD_GET_DATA_INIT] = "TA_EDGE_CMD_GET_DATA_INIT";
  commands[TA_EDGE_CMD_GET_DATA]      = "TA_EDGE_CMD_GET_DATA";

  commands[TA_EDGE_CMD_POLL_FETCH]    = "TA_EDGE_CMD_POLL_FETCH";
  commands[TA_EDGE_CMD_POLL_DATA]     = "TA_EDGE_CMD_POLL_DATA";
  commands[TA_EDGE_CMD_POLL_IO]     = "TA_EDGE_CMD_POLL_IO";

  commands[TA_EDGE_CMD_LOAD]          = "TA_EDGE_CMD_LOAD";
  commands[TA_EDGE_CMD_STORE]         = "TA_EDGE_CMD_STORE";

  commands[TA_EDGE_CMD_FALLBACK_INIT]   = "TA_EDGE_CMD_FALLBACK_INIT";
  commands[TA_EDGE_CMD_FALLBACK_FRONT]  = "TA_EDGE_CMD_FALLBACK_FRONT";
  commands[TA_EDGE_CMD_FALLBACK_BACK]   = "TA_EDGE_CMD_FALLBACK_BACK";

  commands[TA_EDGE_NXT_EXIT]          = "TA_EDGE_NXT_EXIT";
  commands[TA_EDGE_CMD_TEST]          = "TA_EDGE_CMD_TEST";

  effinish();
}

const char *cmd_to_str(int num)
{
  efstart("num: %d", num);
  effinish("ret: %s", commands[num]);
  return commands[num];
}

