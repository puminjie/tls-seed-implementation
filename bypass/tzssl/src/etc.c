#include "cust_func.h"
#include <sys/time.h>

int uname(struct utsname *buf)
{
  return 0;
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    struct timeval *timeout)
{
  return -1;
}
