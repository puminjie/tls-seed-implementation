#include <unistd.h>

#define FAKE_PIPE_READ_FD 0xFAFAFAFALL
#define FAKE_PIPE_WRITE_FD 0xFBFBFBFBLL
#define _SC_PAGESIZE 11
#define TZ_PAGE_SIZE 0x1000

int pipe(int pipefd[2])
{
  pipefd[0] = FAKE_PIPE_READ_FD;
  pipefd[1] = FAKE_PIPE_WRITE_FD;

  return 0;
}

long sysconf(int name)
{
  if (name == _SC_PAGESIZE)
  {
    return TZ_PAGE_SIZE;
  }

  return TZ_PAGE_SIZE;
}

int getpid()
{
  return 0;
}

struct dirent *readdir(void *dirp)
{
  return NULL;
}

int closedir(void *dirp)
{
  return -1;
}

void *opendir(const char *name)
{
  return NULL;
}
