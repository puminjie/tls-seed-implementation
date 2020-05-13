#include "signal.h"

int sigfillset(sigset_t *set)
{
  return 0;
}

int sigdelset(sigset_t *set, int signum)
{
  return 0;
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
  return 0;
}

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
  return 0;
}

int sigsetjmp(sigjmp_buf env, int savesigs)
{
  return 0;
}

int __sigsetjmp(sigjmp_buf env, int savesigs)
{
  return 0;
}

void siglongjmp(sigjmp_buf env, int val)
{
}
