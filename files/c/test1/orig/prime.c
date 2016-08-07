#include <stdio.h>
#include <limits.h>
#include <sys/types.h>
#include <unistd.h>

static char s_buf[16];

char *
foo(int i) {
  static char buf[16];
  sprintf(buf, "%d", i);
  return buf;
}

int
bar(int n) {
  int j;
  if (n < 4) {
    return 1;
  }
  for (j = 2; j < n; j++) {
    if (n % j == 0) {
      return 0;
    }
  }
  return 1;
}

int
baz() {
  int i;
  static int p = 1;
  for (i = p; i < INT_MAX; i++) {
    if (bar(i)) {
      p = i + 1;
      return i;
    }
  }
  p = 1;
  return p;
}

int main() {
  sprintf(s_buf, "[pid:%d] ", getpid());
  int i;
  for (i = 1; i < 10000; i++) {
    printf("%s %d", s_buf, baz());
    char buff[3];
    fgets (buff, 3, stdin);
  }
  return 0;
}
