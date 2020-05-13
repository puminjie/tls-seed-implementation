#ifndef __CUST_FUNC_H__
#define __CUST_FUNC_H__

#define stderr 2
#include <sys/time.h>
#include <stddef.h>

typedef int key_t;

struct utsname 
{
  char sysname[9];
  char nodename[9];

  char release[9];
  char version[9];
  char machine[9];
#ifdef _GNU_SOURCE
  char domainname[9];
#endif
};

typedef struct {
  int fd_bits[1024];
} fd_set;

// String related functions
long int strtol(const char *str, char **endptr, int base);
size_t strlcpy(char *dst, const char *src, size_t dsize);

// Memory related functions
int shmget(key_t key, int size, int shmflg);
void *shmat(int shmid, const void *shmaddr, int shmflg);
int shmdt(const void *shmaddr);

// Socket related functions
int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    struct timeval *timeout);

// Etc.
int uname(struct utsname *buf);
#endif /* __CUST_FUNC_H__ */
