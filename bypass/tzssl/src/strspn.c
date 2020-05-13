#include <string.h>

/*
 * Span the string s2 (skip characters that are in s2).
 */
size_t
__strspn(const char *s1, const char *s2)
{
  const char *p = s1, *spanp;
  char c, sc; 

  /*  
   * Skip any characters in s2, excluding the terminating \0.
   */
cont:
  c = *p++;
  for (spanp = s2; (sc = *spanp++) != 0;) 
    if (sc == c)
      goto cont;
  return (p - 1 - s1);
}


size_t
strspn(const char *s1, const char *s2)
{
  return __strspn(s1, s2);
}

