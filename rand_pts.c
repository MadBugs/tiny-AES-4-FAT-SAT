#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#define AES_KEYLEN 16

int main(int argc, char *argv[])
{
  uint8_t key_random[AES_KEYLEN];
  int n;

  srand(11223347); //RAND (SEEDING) any number can be used

  for (n=0; n<AES_KEYLEN; n++) key_random[n] = rand();  // gets random bytes, one by one 
  printf("\n\nRANDOM Generated Key={");
  for (n=0; n<AES_KEYLEN-1; n++) printf("%02x,", key_random[n]);
  printf("%02x};\n\n",  key_random[n]);

}
