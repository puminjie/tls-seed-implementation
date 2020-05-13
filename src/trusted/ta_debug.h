#ifndef __CMD_STR_H__
#define __CMD_STR_H__

#define MAX_COMMANDS 256

#include <stdio.h>
#include <cmds.h>
#include <debug.h>

static const char *commands[MAX_COMMANDS]; 

void init_commands(void);
const char *cmd_to_str(int num);

#endif /* __CMD_STD_H__ */
