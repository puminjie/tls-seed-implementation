#include <stdlib.h>
#include "cust_func.h"

int atoi(const char *str)
{
  return (int)strtol(str, (char **)NULL, 10);
}
