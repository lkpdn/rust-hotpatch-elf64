#include <stdio.h>
#include <limits.h>
#include <sys/types.h>
#include <unistd.h>

extern int bar(int);
//XXX: workaround
extern char s_buf[16];

int
baz() {
  int i;
  static int p = 1;
  sprintf(s_buf, "[PID:%d] ", getpid());
  for (i = p; i < INT_MAX; i++) {
    if (bar(i)) {
      p = i + 1;
      return -i;
    }
  }
  p = -1;
  return p;
}
