#include <string.h>

char *strrchr(const char *p, int ch)
{
  char *save;

  for (save = NULL;; ++p)
  {
    if (*p == ch)
      save = (char *)p;
    if (!*p)
      return save;
  }
}
