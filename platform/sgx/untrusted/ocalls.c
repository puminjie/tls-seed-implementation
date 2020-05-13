#ifdef PLATFORM_SGX

#include <stdio.h>
#include <edge.h>

void ocall_print(const char *str)
{
  printf("%s", str);
}

size_t ocall_recv(int fd, void *buf, size_t len, int flags)
{
  return recv(fd, buf, len, flags);
}

size_t ocall_send(int fd, const void *buf, size_t len, int flags)
{
  return send(fd, buf, len, flags);
}

unsigned int ocall_get_current_seconds(void)
{
  return get_current_seconds();
}

unsigned long ocall_get_current_time(void)
{
  return get_current_time();
}

unsigned long ocall_get_current_cpu(void)
{
  return get_current_cpu();
}
#endif /* PLATFORM_SGX */
