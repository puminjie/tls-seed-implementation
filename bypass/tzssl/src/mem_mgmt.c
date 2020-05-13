#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define FAKE_DEV_ZERO_FD 99
#define PAGE_SIZE ((uint64_t) 0x1000)
#define PROT_NONE 0x0
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define MAP_ANON 0x20
#define MAP_PRIVATE 0x02

#define MADV_DONTDUMP 16
#define MAP_FAILED (void *)-1

#define NUM_OF_BUCKETS 10

typedef long int __off_t;

static int lock = 0;

struct mmap_info
{
  uint64_t addr;
  void *m_malloc_addr;
  size_t m_length;
  struct mmap_info *next;
};

struct addr_map
{
  struct mmap_info *ptr[NUM_OF_BUCKETS];
};

static struct addr_map addr_info_map;

void add_addr_info_map(struct addr_map map, void *addr, struct mmap_info *info);
void del_addr_info_map(struct addr_map map, void *addr);

static void *mmap_alloc(size_t length)
{
  struct mmap_info *info;
  void *malloc_addr, *ret_addr;
  uint64_t addr;

  info = NULL;
  malloc_addr = malloc(length + PAGE_SIZE);
  if (!malloc_addr)
  {
    return NULL;
  }

  addr = (uint64_t) malloc_addr;
  addr += PAGE_SIZE;
  addr &= ~(PAGE_SIZE -1);
  ret_addr = (void *)addr;

  info = (struct mmap_info *)malloc(sizeof(struct mmap_info));

  if (!info)
  {
    free(malloc_addr);
    return NULL;
  }

  memset(info, 0x0, sizeof(struct mmap_info));
  info->m_malloc_addr = malloc_addr;
  info->m_length = length;

  // TODO: Is this okay?
  while (lock) {}
  lock = 1;
  add_addr_info_map(addr_info_map, ret_addr, info);
  lock = 0;

  return ret_addr;
}

static void mmap_free(struct mmap_info *mmap)
{
  uint64_t addr;
  addr = mmap->addr;
  free(mmap->m_malloc_addr);
  while (lock) {}
  lock = 1;
  del_addr_info_map(addr_info_map, (void *)addr);
  lock = 0;
}

void *mmap(void *addr, size_t len, int prot, int flags, int fd, __off_t offset)
{
  void *mem_addr;
  mem_addr = NULL;
/*
  if (addr != NULL ||
      prot != (PROT_READ | PROT_WRITE) ||
      (flags != (MAP_ANON | MAP_PRIVATE) && fd != -1) ||
      (flags != MAP_PRIVATE && fd != FAKE_DEV_ZERO_FD) ||
      offset != 0)
  {
    return MAP_FAILED;
  }

  mem_addr = mmap_alloc(len);
  if (!mem_addr)
  {
    errno = 12;
    return MAP_FAILED;
  }

  memset(mem_addr, 0, len);
*/
  return mem_addr;
}

int munmap(void *addr, size_t len)
{
/*
  while (lock) {}
  lock = 1;

  // Critical Section

  lock = 0;
*/
  return 0;
}

int mprotect(void *addr, size_t len, int prot)
{
  return -1;
}

int madvise(void *addr, size_t len, int advice)
{
  if (advice != MADV_DONTDUMP)
    return -1;

  return 0;
}

int mlock(const void * __addr, size_t __len)
{
  return 0;
}
