#include <string.h>
#include "cust_func.h"

size_t
__digits10(unsigned int num)
{
  size_t i = 0;

  do {
    num /= 10;
    i++;
  } while (num != 0);

  return i;
}

int
__itoa(int num, int sign, char *buffer, size_t start, size_t end)
{
  size_t pos;
  unsigned int a;
  int neg;

  if (sign && num < 0)
  {
    a = num;
    neg = 1;
  }
  else
  {
    a = num;
    neg = 0;
  }

  pos = start + __digits10(a);
  if (neg)
    pos++;

  if (pos < end)
    buffer[pos] = '\0';
  else
    return -100;
  pos--;
  do {
    buffer[pos] = (a % 10) + '0';
    pos--;
    a /= 10;
  } while (a != 0);
  if (neg)
    buffer[pos] = '-';
  return 0;
}

int
__num2string(int num, int sign, int setid, char *buf, size_t buflen,
    const char *const list[], size_t max, const char *def)
{
  int ret = 0;
  size_t len;

  (void *)&setid;
  if (0 <= num && num < max)
  {
    len = strlcpy(buf, list[num], buflen);
    if (len >= buflen)
      ret = -100;
  }
  else
  {
    len = strlcpy(buf, def, buflen);
    if (len >= buflen)
      ret = -100;
    else
    {
      ret = __itoa(num, sign, buf, len, buflen);
      if (ret == 0)
        ret = -200;
    }
  }
  return ret;
}

int
strerror_r(int errnum, char *strerrbuf, size_t buflen)
{
  return 0;
}

int
__xpg_strerror_r(int errnum, char *strerrbuf, size_t buflen)
{
  return 0;
}

char *
strerror(int num)
{
  static char buf[255];
  (void)strerror_r(num, buf, sizeof(buf));
  return (buf);
}
