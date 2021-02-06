#include <stdio.h>

int main(int argc, char** argv) {

  int i = 0;
  while (i <= 9) {
    if (i & 1 != 0) {
      printf("%d\n", i);
    }
    i++;
  }

  return 1;
}
