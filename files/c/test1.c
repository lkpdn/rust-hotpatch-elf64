#include <stdio.h>

static char s_buf[16];

int main(){
  sprintf(s_buf, "%016x", 4649);
  printf("%s\n", s_buf);
  return 0;
}
