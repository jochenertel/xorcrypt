/***************************************************************************************************
 *
 * file     : shatest.c
 * function : test of sha256 code against open ssl
 * author   : Jochen Ertel
 * created  : 12.12.2018
 * updated  : 04.03.2023
 *
 **************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <openssl/hmac.h>

#include "sha256.h"



/***************************************************************************************************
 * helper functions
 **************************************************************************************************/

typedef struct {
  uint32_t k;
  uint32_t d1;
  uint32_t d2;
  uint32_t d3;
} shapar_t;



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
  HMAC_CTX *ctx_hmac; /* open SSL */
  hmac_sha256_ctx_t ctx_own;
  shapar_t run[5];
  uint32_t i, max;
  uint8_t  key[200], da1[200], da2[200], da3[200], mac_ssl[32], mac_own[32];
  long ti1, ti2;

  /* define parameters of 5 test runs */
  run[0].k = 16; run[0].d1 = 16; run[0].d2 = 16; run[0].d3 = 16;
  run[1].k = 63; run[1].d1 =  3; run[1].d2 = 27; run[1].d3 = 40;
  run[2].k = 64; run[2].d1 = 65; run[2].d2 = 99; run[2].d3 =  1;
  run[3].k = 70; run[3].d1 = 63; run[3].d2 =  1; run[3].d3 = 12;
  run[4].k = 47; run[4].d1 =  0; run[4].d2 = 88; run[4].d3 = 16;


  printf ("-----------------------------------------------------------------------------------------------------------\n");
  printf ("(1) Proof of correct implementation -----------------------------------------------------------------------\n");
  printf ("-----------------------------------------------------------------------------------------------------------\n");
  for (i=0; i < 5; i++) {

    printf ("-> run %lu ---------------------------------------------------------\n", (unsigned long) (i+1));
    get_random (key, run[i].k);
    get_random (da1, run[i].d1);
    get_random (da2, run[i].d2);
    get_random (da3, run[i].d3);

    ctx_hmac = HMAC_CTX_new();
    HMAC_Init_ex (ctx_hmac, (unsigned char *) key, (size_t) run[i].k, EVP_sha256(), NULL);
    HMAC_Update (ctx_hmac, (unsigned char *) da1, (size_t) run[i].d1);
    HMAC_Update (ctx_hmac, (unsigned char *) da2, (size_t) run[i].d2);
    HMAC_Update (ctx_hmac, (unsigned char *) da3, (size_t) run[i].d3);
    HMAC_Final (ctx_hmac, (unsigned char *) mac_ssl, NULL);
    HMAC_CTX_free (ctx_hmac);

    hmac_sha256_init   (&ctx_own, key, (size_t) run[i].k);
    hmac_sha256_update (&ctx_own, da1, (size_t) run[i].d1);
    hmac_sha256_update (&ctx_own, da2, (size_t) run[i].d2);
    hmac_sha256_update (&ctx_own, da3, (size_t) run[i].d3);
    hmac_sha256_final  (&ctx_own, mac_own);


    print_bin ("key", 10, 32, key, run[i].k);
    print_bin ("da1", 10, 32, da1, run[i].d1);
    print_bin ("da2", 10, 32, da2, run[i].d2);
    print_bin ("da3", 10, 32, da3, run[i].d3);
    printf ("\n");
    print_bin ("mac_ssl", 10, 32, mac_ssl, 32);
    print_bin ("mac_own", 10, 32, mac_own, 32);
    printf ("\n\n\n");
  }



  printf ("-----------------------------------------------------------------------------------------------------------\n");
  printf ("(2) Proof of performance (calculation of 200 mill. HMACs) -------------------------------------------------\n");
  printf ("-----------------------------------------------------------------------------------------------------------\n");
  max = 200000000;

  printf ("-> run 1 (open ssl) ------------------------------------------------\n");

  ti1 = (long) time(NULL); /* get unix-time in seconds */
  printf ("run ssl hmac loop ...\n");

  ctx_hmac = HMAC_CTX_new();
  HMAC_Init_ex (ctx_hmac, (unsigned char *) key, (size_t) run[4].k, EVP_sha256(), NULL);
  for (i=0; i < max; i++)
    HMAC_Update (ctx_hmac, (unsigned char *) da3, (size_t) run[4].d3);
  HMAC_Final (ctx_hmac, (unsigned char *) mac_ssl, NULL);
  HMAC_CTX_free (ctx_hmac);

  ti2 = ((long) time(NULL)) - ti1; /* get unix-time difference in seconds */
  printf ("time: %u s\n", (unsigned int) ti2);
  printf ("\n");


  printf ("-> run 2 (own code) ------------------------------------------------\n");

  ti1 = (long) time(NULL); /* get unix-time in seconds */
  printf ("run own hmac loop ...\n");

  hmac_sha256_init   (&ctx_own, key, (size_t) run[4].k);
  for (i=0; i < max; i++)
    hmac_sha256_update (&ctx_own, da3, (size_t) run[4].d3);
  hmac_sha256_final  (&ctx_own, mac_own);

  ti2 = ((long) time(NULL)) - ti1; /* get unix-time difference in seconds */
  printf ("time: %u s\n", (unsigned int) ti2);


  return (0);
}



