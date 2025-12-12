#include <stdio.h>

int add(int x, int y)
{
  return x + y;
}

int main()
{
  int a = 5;
  int b = 7;
  int c = add(a, b);
  printf("Result: %d\n", c);

  for (int i = 0; i < 3; i++)
  {
    printf("i = %d\n", i);
  }

  return 0;
}
