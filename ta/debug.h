#ifndef __CMD_STR_H__
#define __CMD_STR_H__

#define MAX_COMMANDS 256

#include <ta_edge_cache.h>

static char *commands[MAX_COMMANDS]; 

void init_commands(void);
char *cmd_to_str(int num);

#endif /* __CMD_STD_H__ */
