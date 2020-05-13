#include <string.h>
#define PATH_DEV_NULL "/dev/null"

char *secure_getenv(const char *name)
{
  if (name == NULL)
  {
    return NULL;
  }

  if (!strcmp(name , "OPENSSL_CONF"))
  {
    return NULL;
  }

  if (!strcmp(name, "OPENSSL_ENGINES"))
  {
    return (char *) PATH_DEV_NULL;
  }

  if (!strcmp(name, "OPENSSL_ALLOW_PROXY_CERTS"))
  {
    return NULL;
  }

  if (!strcmp(name, "OPENSSL_ia32cap"))
  {
    return NULL;
  }

  return NULL;
}

int atexit(void (*function)(void))
{
  return 0;
}
