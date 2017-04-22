/***************************************************************************************************
 *
 * file     : xorcrypt.c (one source code file only, tool depends on OpenSSL crypto API)
 * function : file encryption tool, designed by Jochen Ertel, features are:
 *            - encryption with AES256 in Counter Mode
 *            - integrity protection with SHA256 in HMAC mode
 *            - AES and HMAC keys are derived from a password with PBKDF2 algorithm
 *            - OpenSSL implementations of AES256 and HMAC-SHA256 are used
 *              (note: under Ubuntu-, Debian-Linux: package libssl-dev must be installed)
 * author   : Jochen Ertel
 * created  : 16.09.2016
 * updated  : 22.04.2017
 *
 **************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/aes.h>
#include <openssl/hmac.h>


#define VERSION "xorcrypt - file encryption tool developed by Jochen Ertel (version 1.0.0)"

#define PBKDF2_ROUND_NUMBER  1000000




/***************************************************************************************************
 * functions for reading command line options and printing error messages
 **************************************************************************************************/

/* function : parArgTypExists ()
 *            -> checks whether an argument typ exists or not
 *               (an argument typ of programm call consists of 1 character
 *               with a leading '-')
 *            -> returns 0 if argument does not exist or the index of argument
 *               type in the argv[] array
 ******************************************************************************/
int parArgTypExists (int argc, char *argv[], char argType)
{
  int  i;
  char tmp[3];

  tmp[0] = '-';
  tmp[1] = argType;
  tmp[2] = 0;

  if (argc > 1) {
    for (i = 1; i < argc; i++) {
      if (!strcmp (argv[i], tmp))
        return (i);
    }
  }
  return (0);
}


/* function : parGetString ()
 *            -> gets string argument value
 *            -> returns 0 in error case, returns 1 if OK
 *               (string is limited to max. 1024 characters)
 ******************************************************************************/
int parGetString (int argc, char *argv[], char argType, char *value)
{
  int a;

  a = parArgTypExists (argc, argv, argType);

  /* error checking */
  if (a == 0) return (0);
  if (a >= (argc -1)) return (0);
  if (strlen(argv[a+1]) > 1024) return (0);

  strcpy(value, argv[a+1]);
  return (1);
}


/* function : error_and_exit ()
 *            -> prints error message and exit with return code 1
 ******************************************************************************/
void error_and_exit (char *message)
{
  fprintf (stderr, "xorcrypt: error: %s\n", message);
  exit (1);
}




/***************************************************************************************************
 * crypto functions
 **************************************************************************************************/

/* PBKDF2 function based on HMAC-SHA-256
 *   in : *salt   -> salt of length slen byte
 *        slen    -> length of salt in byte (valid values are from 0 to 32)
 *        *pwd    -> password (c-string, length 0 to 64 byte)
 *        rounds  -> number of rounds (1, 2, 3, ...)
 *   out: *key    -> hash result = output key value of fix length of 32 byte (256 bit)
 ****************************************************************************************/
void pbkdf2 (unsigned char *salt, size_t slen, char *pwd, size_t rounds, unsigned char *key)
{
  unsigned char msg[36], acckey[32], digest[32], *ret;
  size_t i, k, plen, len;

  /* generate input message (extended salt) *************************/
  if (slen > 32)
    error_and_exit ("internal problem (pbkdf2 salt size to large)");
  for (i=0; i < slen ; i++) {
    msg[i] = salt[i];
  }
  msg[slen + 0] = 0x00;
  msg[slen + 1] = 0x00;
  msg[slen + 2] = 0x00;
  msg[slen + 3] = 0x01;


  /* initialise accumulate vector ***********************************/
  for (i=0; i < 32 ; i++) {
    acckey[i] = 0x00;
  }


  /* check password string ******************************************/
  plen = strlen(pwd);
  if (plen > 63)
    error_and_exit ("invalid password (is larger than 63 characters)");

  for (i=0; i < plen; i++) {
    if (((unsigned char) pwd[i]) > 127)
      error_and_exit ("invalid password (contains non-ascii characters)");
  }

  plen++; /* note: extend password string always by 0x00 (marker of string end)
                  -> this has no influence to pbkdf2 because password string
                     is always padded with 0x00 bytes to total size of 64 byte
                     inside HMAC algorithm (password is used as HMAC-key) */

  if (rounds == 0)
    error_and_exit ("internal problem (pbkdf2 round number is zero)");

  len = slen + 4;

  /* do the rounds **************************************************/
  for (k=0; k < rounds ; k++) {

    ret = HMAC(EVP_sha256(), (unsigned char*) pwd, (int) plen, msg, (int) len,
               digest, NULL);
    if (ret == NULL)
      error_and_exit ("internal problem (openssl hmac error)");

    for (i=0; i < 32 ; i++) {
      acckey[i] = acckey[i] ^ digest[i];
      msg[i] = digest[i];
    }
    len = 32;
  }

  /* copy output key ************************************************/
  for (i=0; i < 32 ; i++) {
    key[i] = acckey[i];
  }
}




/***************************************************************************************************
 * self test values
 **************************************************************************************************/

unsigned char st_aes_key[32] =    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                   0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

unsigned char st_aes_plain[16] =  {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                   0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

unsigned char st_aes_cipher[16] = {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
                                   0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};

unsigned char st_hmac_key[32] =   {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                                   0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                                   0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                                   0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};

unsigned char st_hmac_msg[8] =    {0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65};

unsigned char st_hmac_mac[32] =   {0xa2, 0x5f, 0xde, 0x08, 0x75, 0x40, 0x36, 0x07,
                                   0xa2, 0x41, 0xee, 0x0e, 0xb4, 0xc6, 0xf0, 0xa9,
                                   0xc5, 0xd6, 0x01, 0xae, 0xd7, 0xae, 0x35, 0x02,
                                   0x8d, 0xdd, 0x91, 0xe3, 0xac, 0xcc, 0x9a, 0xc8};




/***************************************************************************************************
 * main function
 **************************************************************************************************/

int main (int argc, char *argv[])
{
  FILE *fpr, *fpw;
  size_t i, ib, len1, len2, sizein;
  int mode, istdin, istdout, chint, chk, verbose, st_r1, st_r2;
  long ti, ti_st, scnt_pre, scnt_mb;
  unsigned char enc_key[32], auth_key[32], irandom[32], counter[16], enc_counter[16], readin[16], inbuf[32],
                encdec_readin[16], icv[32], st_temp[32], *retc;
  char timestring[20], modestring[1024], randstring[1024], password[1024], fname_i[1024], fname_o[1024];
  AES_KEY enc_key_aes;
  HMAC_CTX ctx_hmac;



  /* help menu ************************************************************************************/
  if (parArgTypExists (argc, argv, 'h')) {
    printf (VERSION "\n");
    printf ("  -> parameters (optional):\n");
    printf ("     -h            :  prints this help menu\n");
    printf ("     -t            :  self test of crypto functions\n");
    printf ("     -m <char>     :  mode (e: encrypt (default), d: decrypt, c: check integrity)\n");
    printf ("     -i <filename> :  [e|d|c]: file name of binary input file (default: stdin)\n");
    printf ("     -o <filename> :  [e|d]  : file name of binary output file (default: stdout)\n");
    printf ("     -p <string>   :  [e|d|c]: password (0 to 63 ASCII characters, default: empty string)\n");
    printf ("     -r <string>   :  [e]    : additional-random-string for random derivation (default: \"abc\")\n");
    printf ("     -v            :  [e|d|c]: print status information to stderr\n");
    printf ("  -> how it works:\n");
    printf ("     -> file encryption by AES256 in Counter Mode\n");
    printf ("     -> integrity protection of encrypted file by HMAC-SHA256\n");
    printf ("     -> AES and HMAC keys are derived from Password by PBKDF2 function (HMAC-SHA256 based):\n");
    printf ("        - AES key  (256 bit) = PBKDF2 (Salt1, Password, 1.000.000 rounds)\n");
    printf ("        - HMAC key (256 bit) = PBKDF2 (Salt2, Password, 1.000.000 rounds)\n");
    printf ("     -> 32 byte random are derived by HMAC-SHA256 (unix-time, additional-random-string),\n");
    printf ("        random is used for:\n");
    printf ("        - Counter Mode IV (16 byte)\n");
    printf ("        - PBKDF2 Salt1 (8 byte)\n");
    printf ("        - PBKDF2 Salt2 (8 byte)\n");
    printf ("     -> simple output file format:\n");
    printf ("        - random: IV | Salt1 | Salt2 (32 byte)\n");
    printf ("        - encrypted input file (same size as input file)\n");
    printf ("        - integrity check value (32 byte)\n");

    return (0);
  }



  /* self test of crypto functions ****************************************************************/
  if (parArgTypExists (argc, argv, 't')) {
    printf (VERSION "\n");
    printf ("  -> running crypto function self test: \n");

    st_r1 = 0;
    st_r2 = 0;

    /* test of all used open-ssl aes functions */
    printf ("     -> AES self test: ");
    for (i=0; i < 32; i++) st_temp[i] = 0x00;
    AES_set_encrypt_key (st_aes_key, 256, &enc_key_aes);
    AES_encrypt (st_aes_plain, st_temp, &enc_key_aes);
    for (i=0; i < 16; i++) {
      if (st_temp[i] != st_aes_cipher[i]) st_r1++;
    }
    if (st_r1 == 0)
      printf ("OK!\n");
    else
      printf ("FAILED!\n");

    /* test of all used open-ssl hmac-sha256 functions */
    printf ("     -> HMAC-SHA256 self test: ");
    for (i=0; i < 32; i++) st_temp[i] = 0x00;
    retc = HMAC(EVP_sha256(), st_hmac_key, 32, st_hmac_msg, 8, st_temp, NULL);
    if (retc == NULL) st_r2++; /* return error case */
    for (i=0; i < 32; i++) {
      if (st_temp[i] != st_hmac_mac[i]) st_r2++;
    }

    for (i=0; i < 32; i++) st_temp[i] = 0x00;
    HMAC_CTX_init (&ctx_hmac);
    HMAC_Init (&ctx_hmac, st_hmac_key, 32, EVP_sha256());
    HMAC_Update (&ctx_hmac, &st_hmac_msg[0], 5);
    HMAC_Update (&ctx_hmac, &st_hmac_msg[5], 3);
    HMAC_Final (&ctx_hmac, st_temp, NULL);
    HMAC_CTX_cleanup (&ctx_hmac);
    for (i=0; i < 32; i++) {
      if (st_temp[i] != st_hmac_mac[i]) st_r2++;
    }
    if (st_r2 == 0)
      printf ("OK!\n");
    else
      printf ("FAILED!\n");

    if ((st_r1 == 0) && (st_r2 == 0))
      return (0);
    else
      return (1);
  }



  /* reading all parameters ***********************************************************************/
  /* mode *****************************/
  if (parGetString (argc, argv, 'm', modestring) != 1) {
    mode = 0; /* encrypt */
  }
  else {
    if (strlen(modestring) != 1)
      error_and_exit ("invalid mode");
    mode = -1;
    if (modestring[0] == 'e') mode = 0;
    if (modestring[0] == 'd') mode = 1;
    if (modestring[0] == 'c') mode = 2;
    if (mode == -1)
      error_and_exit ("invalid mode");
  }

  /* input file ***********************/
  if (parGetString (argc, argv, 'i', fname_i) == 1) {
    fpr = fopen (fname_i, "rb");
    if (fpr == NULL)
      error_and_exit ("input file can not be opened");
    istdin = 0;
  }
  else {
    fpr = stdin;
    istdin = 1;
  }

  /* output file **********************/
  if (parGetString (argc, argv, 'o', fname_o) == 1) {
    fpw = fopen (fname_o, "wb");
    if (fpw == NULL)
      error_and_exit ("output file can not be opened");
    istdout = 0;
  }
  else {
    fpw = stdout;
    istdout = 1;
  }

  /* password *************************/
  if (parGetString (argc, argv, 'p', password) != 1) {
    password[0] = 0x00;
  }

  /* additional-random-string *********/
  if (parGetString (argc, argv, 'r', randstring) != 1) {
    randstring[0] = 'a';
    randstring[1] = 'b';
    randstring[2] = 'c';
    randstring[3] = 0x00;
  }

  /* verbose mode *********************/
  if (parArgTypExists (argc, argv, 'v') != 0) {
    verbose = 1;
  }
  else {
    verbose = 0;
  }



  /* generation of 32 byte internal random ********************************************************/
  if (mode == 0) {   /* encryption case ********************************************/
    /* generate irandom by HMAC_SHA256(unix-time, additional-random-string) */
    ti = 0;
    ti = (long) time(NULL); /* get unix-time in seconds */
    if (ti <= 0)
      error_and_exit ("internal problem (not able to get time)");
    sprintf(timestring, "%li", ti);

    len1 = strlen(timestring);
    len2 = strlen(randstring);
    retc = HMAC(EVP_sha256(), (unsigned char*) timestring, (int) len1, (unsigned char*) randstring,
                (int) len2, irandom, NULL);
    if (retc == NULL)
      error_and_exit ("internal problem (openssl hmac error)");

    /* write irandom to output file */
    for (i=0; i < 32; i++) fputc (irandom[i], fpw);
  }
  else {   /* decryption or check integrity case ***********************************/
    /* read irandom from input file */
    for (i=0; i < 32; i++) {
      chint = getc(fpr);
      if (chint == EOF)
        error_and_exit ("input file to short");
      irandom[i] = (unsigned char) (chint & 255);
    }
  }



  /* derivation of keys ***************************************************************************/
  if (verbose) fprintf (stderr, "xorcrypt: derivation of keys ...\n");
  if (mode != 2) {  /* need not to be calculated in check integrity mode */
    pbkdf2 (&irandom[16], 8, password, PBKDF2_ROUND_NUMBER, enc_key);
    AES_set_encrypt_key (enc_key, 256, &enc_key_aes); /* openssl aes-key-expansion */
  }
  pbkdf2 (&irandom[24], 8, password, PBKDF2_ROUND_NUMBER, auth_key);
  HMAC_CTX_init (&ctx_hmac);
  HMAC_Init (&ctx_hmac, auth_key, 32, EVP_sha256()); /* openssl hmac initialisation */
  for (i=0; i < 16; i++) counter[i] = irandom[i];   /* copy iv */

  HMAC_Update (&ctx_hmac, irandom, 32); /* hash the 32 byte random at first */



  /* do encryption/decryption *********************************************************************/
  if ((mode == 0) || (mode == 1) || (mode == 2)) {
    /* check for empty input file */
    chint = getc(fpr);

    /* buffer 32 byte of input file in decryption mode */
    if ((mode == 1) || (mode == 2)) {
      ib = 0;
      while ((chint != EOF) && (ib < 32)) {
        inbuf[ib] = (unsigned char) (chint & 255);
        ib++;
        chint = getc(fpr);
      }
      ib = 0;
    }

    if (chint == EOF)
      error_and_exit ("input file to short");


    /* do encryption/decryption and integrity value calculation */
    scnt_mb = 0;
    scnt_pre = 0;
    if (verbose) {
      fprintf (stderr, "xorcrypt: running ... (0 MByte done)\r");
      ti_st = (long) time(NULL);
    }
    do {
      /* read a chunk of max. 16 byte from input file */
      sizein = 0;
      if (mode == 0) {
        while ((chint != EOF) && (sizein < 16)) {
          readin[sizein] = (unsigned char) (chint & 255);
          sizein++;
          chint = getc(fpr);
        }
      }
      if ((mode == 1) || (mode == 2)) {
        while ((chint != EOF) && (sizein < 16)) {
          readin[sizein] = inbuf[ib];
          inbuf[ib] = (unsigned char) (chint & 255);
          ib = (ib + 1) % 32;
          sizein++;
          chint = getc(fpr);
        }
      }

      if (mode != 2) {
        /* encrypt and increment counter */
        AES_encrypt (counter, enc_counter, &enc_key_aes);
        i = 16;
        do {
          i--;
          counter[i] = (counter[i] + 1) & 255;
        } while ((counter[i] == 0) && (i > 0));

        /* encrypt/decrypt input chunk by xoring */
        for (i=0; i < sizein; i++) encdec_readin[i] = readin[i] ^ enc_counter[i];
      }

      /* hash encrypted data */
      if (mode == 0) HMAC_Update (&ctx_hmac, encdec_readin, sizein);  /* encryption mode */
      if ((mode == 1) || (mode == 2)) HMAC_Update (&ctx_hmac, readin, sizein);  /* decryption/check mode */

      if (mode != 2) {
        /* write encrypted/decrypted chunk to output file */
        for (i=0; i < sizein; i++) fputc (encdec_readin[i], fpw);
      }

      /* write status to stderr */
      scnt_pre++;
      if (scnt_pre == 65536) {
        scnt_mb++;
        scnt_pre = 0;
      }
      if ((verbose == 1) && (scnt_pre == 0)) {
        fprintf (stderr, "\rxorcrypt: running ... (%li MByte done)", scnt_mb);
      }

    } while (chint != EOF);

    if (verbose) {
      ti = ((long) time(NULL)) - ti_st;
      fprintf (stderr, "\nxorcrypt: processing finnished");
      if ((ti > 0) && (scnt_mb > 0))
        fprintf (stderr, " (throughput was about %li MByte/sec)\n", (scnt_mb/ti));
      else
        fprintf (stderr, "\n");
    }


    /* finalise hashing by calculating icv */
    HMAC_Final (&ctx_hmac, icv, NULL); /* length of icv is always 32 byte */
    HMAC_CTX_cleanup (&ctx_hmac);

    /* write icv to output file in encryption mode */
    if (mode == 0) {
      for (i=0; i < 32; i++) fputc (icv[i], fpw);
    }

    /* check icv in decryption/check mode */
    if ((mode == 1) || (mode == 2)) {
      chk = 0;
      for (i=0; i < 32; i++) {
        if (icv[i] != inbuf[(i+ib)%32]) chk++;
      }
      if (verbose) {
        if (chk == 0) fprintf (stderr, "xorcrypt: integrity check OK!\n");
        else fprintf (stderr, "xorcrypt: integrity check FAILED!\n");
      }
    }

  }


  if (istdin == 0) fclose(fpr);
  if (istdout == 0) fclose(fpw);

  if (((mode == 1) || (mode == 2)) && (chk != 0)) return (2);
  else return (0);
}



