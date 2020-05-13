#include <time.h>
#include <sys/time.h>

#define CLOCK_REALTIME 0

int clock_gettime(int clk_id, struct timespec *tp)
{
  struct timeval tv;
  (void) (clk_id);

  if (clk_id != CLOCK_REALTIME)
  {
    return -1;
  }

  if (gettimeofday(&tv, NULL) != 0)
  {
    return -1;
  }

  tp->tv_sec = tv.tv_sec;
  tp->tv_nsec = tv.tv_usec;

  return 0;
}

struct tm *gmtime(const time_t *timep)
{
  return gmtime_r(timep, NULL);
}
