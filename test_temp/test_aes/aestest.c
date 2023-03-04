/***************************************************************************************************
 *
 * file     : aestest.c
 * function : test of aes code against open ssl
 * author   : Jochen Ertel
 * created  : 20.01.2019
 * updated  : 04.03.2023
 *
 **************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <openssl/aes.h>

#include "aes.h"



/***************************************************************************************************
 * helper functions
 **************************************************************************************************/

void get_random (uint8_t *r, uint32_t len)
{
  FILE *fpr;
  int chint;
  uint32_t i;

  fpr = fopen ("/dev/urandom", "rb");

  for (i=0; i < len; i++) {
    chint = getc(fpr);
    r[i] = (uint8_t) (chint & 255);
  }

  fclose(fpr);
}



void convBin2HexByte (uint8_t bin, char *hexByte)
{
  int8_t  i;
  uint8_t a[2];

  a[0] = bin & 15;
  a[1] = bin >> 4;

  for (i = 1; i >= 0; i--) {
    if (a[i] == 0)  hexByte[1-i] = '0';
    if (a[i] == 1)  hexByte[1-i] = '1';
    if (a[i] == 2)  hexByte[1-i] = '2';
    if (a[i] == 3)  hexByte[1-i] = '3';
    if (a[i] == 4)  hexByte[1-i] = '4';
    if (a[i] == 5)  hexByte[1-i] = '5';
    if (a[i] == 6)  hexByte[1-i] = '6';
    if (a[i] == 7)  hexByte[1-i] = '7';
    if (a[i] == 8)  hexByte[1-i] = '8';
    if (a[i] == 9)  hexByte[1-i] = '9';
    if (a[i] == 10) hexByte[1-i] = 'a';
    if (a[i] == 11) hexByte[1-i] = 'b';
    if (a[i] == 12) hexByte[1-i] = 'c';
    if (a[i] == 13) hexByte[1-i] = 'd';
    if (a[i] == 14) hexByte[1-i] = 'e';
    if (a[i] == 15) hexByte[1-i] = 'f';
  }

  hexByte[2] = 0;
}



/* write binary byte stream formatted to stdout
 *   in : *name        -> name of bytestream (string)
 *        ind          -> indentation of byte stream
 *        num          -> number of bytes per line
 *        *bytestream  -> pointer to byte stream
 *        len          -> length of byte stream
 *   out: -
 *
 ****************************************************************************************/
void print_bin (const char *name, uint32_t ind, uint32_t num, uint8_t *bytestream, uint32_t len)
{
  uint32_t ln, i, j;
  char hexbyte[3];

  ln = (uint32_t) strlen (name);

  printf("%s = ", name);

  if (ind > (ln+3))
    for (i=0; i < (ind-ln-3); i++) printf(" ");

  printf("{");

  for (i=0; i < len; i++) {
    convBin2HexByte (bytestream[i], hexbyte);
    printf("%s", hexbyte);
    if ((((i+1)%num) == 0) && ((i+1) != len)) {
      printf("\n");
      for (j=0; j < ind; j++) printf(" ");
    }
    if ((i+1) != len) printf(" ");
  }
  printf("}\n");
}





/***************************************************************************************************
 * main function
 **************************************************************************************************/

int main (int argc, char *argv[])
{
  AES_KEY ssl_key_aes; /* open SSL */
  aes_ctx_t ctx_own;
  uint32_t i, max;
  uint8_t  key[32], da[16], das[16], cy1[16], cy2[16];
  long ti1, ti2;

  printf ("-----------------------------------------------------------------------------------------------------------\n");
  printf ("(1) Proof of correct implementation -----------------------------------------------------------------------\n");
  printf ("-----------------------------------------------------------------------------------------------------------\n");

  printf ("-> aes key size 128 bit --------------------------------------------\n");
  get_random (key, 16);
  get_random (da,  16);

  AES_set_encrypt_key ((unsigned char *) key, 128, &ssl_key_aes);
  AES_encrypt ((unsigned char *) da, (unsigned char *) cy1, &ssl_key_aes);

  aes_init (&ctx_own, key, 16);
  aes_encrypt (&ctx_own, da, cy2);
  aes_decrypt (&ctx_own, cy2, das);

  print_bin ("key", 10, 32, key, 16);
  print_bin ("da", 10, 32, da, 16);
  printf ("\n");
  print_bin ("cy_ssl", 10, 32, cy1, 16);
  print_bin ("cy_own", 10, 32, cy2, 16);
  printf ("\n");
  print_bin ("da'_own", 10, 32, das, 16);
  printf ("\n\n\n");


  printf ("-> aes key size 192 bit --------------------------------------------\n");
  get_random (key, 24);
  get_random (da,  16);

  AES_set_encrypt_key ((unsigned char *) key, 192, &ssl_key_aes);
  AES_encrypt ((unsigned char *) da, (unsigned char *) cy1, &ssl_key_aes);

  aes_init (&ctx_own, key, 24);
  aes_encrypt (&ctx_own, da, cy2);
  aes_decrypt (&ctx_own, cy2, das);

  print_bin ("key", 10, 32, key, 24);
  print_bin ("da", 10, 32, da, 16);
  printf ("\n");
  print_bin ("cy_ssl", 10, 32, cy1, 16);
  print_bin ("cy_own", 10, 32, cy2, 16);
  printf ("\n");
  print_bin ("da'_own", 10, 32, das, 16);
  printf ("\n\n\n");


  printf ("-> aes key size 256 bit --------------------------------------------\n");
  get_random (key, 32);
  get_random (da,  16);

  AES_set_encrypt_key ((unsigned char *) key, 256, &ssl_key_aes);
  AES_encrypt ((unsigned char *) da, (unsigned char *) cy1, &ssl_key_aes);

  aes_init (&ctx_own, key, 32);
  aes_encrypt (&ctx_own, da, cy2);
  aes_decrypt (&ctx_own, cy2, das);

  print_bin ("key", 10, 32, key, 32);
  print_bin ("da", 10, 32, da, 16);
  printf ("\n");
  print_bin ("cy_ssl", 10, 32, cy1, 16);
  print_bin ("cy_own", 10, 32, cy2, 16);
  printf ("\n");
  print_bin ("da'_own", 10, 32, das, 16);
  printf ("\n\n\n");


  printf ("-----------------------------------------------------------------------------------------------------------\n");
  printf ("(2) Proof of performance (calculation of 100 mill. encryptions) -------------------------------------------\n");
  printf ("-----------------------------------------------------------------------------------------------------------\n");
  max = 100000000;

  printf ("-> run 1: encryption with 256 bit key (open ssl) -------------------\n");

  ti1 = (long) time(NULL); /* get unix-time in seconds */
  printf ("run ssl aes loop ...\n");

  AES_set_encrypt_key ((unsigned char *) key, 256, &ssl_key_aes);
  for (i=0; i < max; i++)
    AES_encrypt ((unsigned char *) da, (unsigned char *) cy1, &ssl_key_aes);

  ti2 = ((long) time(NULL)) - ti1; /* get unix-time difference in seconds */
  printf ("time: %u s\n", (unsigned int) ti2);
  printf ("\n");


  printf ("-> run 2: encryption with 256 bit key (own code) -------------------\n");

  ti1 = (long) time(NULL); /* get unix-time in seconds */
  printf ("run own aes loop ...\n");

  aes_init (&ctx_own, key, 32);
  for (i=0; i < max; i++)
    aes_encrypt (&ctx_own, da, cy2);

  ti2 = ((long) time(NULL)) - ti1; /* get unix-time difference in seconds */
  printf ("time: %u s\n", (unsigned int) ti2);


  return (0);
}



