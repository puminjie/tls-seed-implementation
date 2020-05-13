#ifndef __SIGNAL_H__
#define __SIGNAL_H__

#if !defined(__ACK__) && !defined(__BCC__) && !defined(__GNUC__)
#define __ACK__
#endif

#ifdef __ACK__
#define _SETJMP_SYMBOL 1
#define _SETJMP_SAVES_REGS 0
#endif 
#ifdef __BCC__
#define _SETJMP_SYMBOL 0
#define _SETJMP_SAVES_REGS 1
#endif
#ifdef __GNUC__
#define _SETJMP_SYMBOL 0
#define _SETJMP_SAVES_REGS 1
#endif

typedef struct {
  int si_signo;
  int si_errno;
  int si_code;
  int si_trapno;

  // Not Implemented (Not needed)
} siginfo_t;

typedef struct {
  unsigned int __sigbits[4];
} sigset_t;

typedef struct {
  int __flags;
  long __mask;
#if (_SETJMP_SAVES_REGS == 0)
  _PROTOTYPE(void (* __pc), (void));
  void *__sp;
  void *__lb;
#else
  void *__regs[16];
#endif
} sigjmp_buf;

struct sigaction {
  void (*sa_handler)(int);
  void (*sa_sigaction)(int, siginfo_t *, void *);
  sigset_t sa_mask;
  int sa_flags;
  void (*sa_restorer)(void);
};
#endif /* __SIGNAL_H__ */
