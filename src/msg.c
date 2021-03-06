#include <ctype.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

#define VERSION "v0.0.1"
#define SIGNSECRETKEYPATH "signing.prv"
#define SIGNPUBLICKEYPATH "signing.pub"

void usage(char *name){
  puts("MSG - Simple libsodium signing tool");
  puts(VERSION);
  printf("Usage: %s COMMAND PARAMTERS\n\nCOMMAND can be generate/export/sign/verify.\n", name);
  puts("PARAMETERS:\n\tgenerate - none\n\texport - none\n\tsign - MESSAGE\n\tverify - MESSAGE SIGNATURE PUBLICKEY");
  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
  if (argc < 2)
    usage(argv[0]);
  assert(sodium_init() == 0);
  char *cmd = argv[1];
  char *i = cmd;
  for(;*i;i++) *i = tolower(*i);
  if (strcmp(cmd, "generate") == 0) {
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);
    FILE *fp;
    fp = fopen(SIGNPUBLICKEYPATH, "wb");
    assert(NULL != fp);
    fwrite(pk, 1, crypto_sign_PUBLICKEYBYTES, fp);
    fclose(fp);
    fp = fopen(SIGNSECRETKEYPATH, "wb");
    assert(NULL != fp);
    fwrite(sk, 1, crypto_sign_SECRETKEYBYTES, fp);
    fclose(fp);
  }else if (strcmp(cmd, "export") == 0){
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    char pk_hd[crypto_sign_PUBLICKEYBYTES*2+1];
    char sk_hd[crypto_sign_SECRETKEYBYTES*2+1];
    FILE *fp;
    fp = fopen(SIGNSECRETKEYPATH, "rb");
    assert(NULL != fp);
    fread(sk, 1, crypto_sign_SECRETKEYBYTES, fp);
    fclose(fp);
    fp = fopen(SIGNPUBLICKEYPATH, "rb");
    assert(NULL != fp);
    fread(pk, 1, crypto_sign_PUBLICKEYBYTES, fp);
    fclose(fp);
    sodium_bin2hex(pk_hd, crypto_sign_PUBLICKEYBYTES*2+1,
		   pk, crypto_sign_PUBLICKEYBYTES);
    sodium_bin2hex(sk_hd, crypto_sign_SECRETKEYBYTES*2+1,
		   sk, crypto_sign_SECRETKEYBYTES);
    printf("Secret: %s\nPublic: %s\n", sk_hd, pk_hd);
  }else if (strcmp(cmd, "sign") == 0) {
    if(argc != 3) usage(argv[0]);
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    char *msg = argv[2];
    size_t msg_len = strlen(msg);
    FILE *fp;
    fp = fopen(SIGNSECRETKEYPATH, "rb");
    assert(NULL != fp);
    fread(sk, 1, crypto_sign_SECRETKEYBYTES, fp);
    fclose(fp);
    char sig[crypto_sign_BYTES];    
    crypto_sign_detached(sig, NULL, msg, msg_len, sk);
    char sig_hd[crypto_sign_BYTES*2+1];
    sodium_bin2hex(sig_hd, crypto_sign_BYTES*2+1, sig, crypto_sign_BYTES);
    puts(sig_hd);
  }else if (strcmp(cmd, "verify") == 0) {
    if(argc != 5) usage(argv[0]);
    char *msg = argv[2];
    size_t msg_len = strlen(msg);
    char *sig_hd = argv[3];
    char *pk_hd = argv[4];
    char pk[crypto_sign_PUBLICKEYBYTES];
    char sig[crypto_sign_BYTES];
    size_t bytes;
    sodium_hex2bin(pk, crypto_sign_PUBLICKEYBYTES,
		   pk_hd, strlen(pk_hd),
		   " \r\n\t", &bytes, NULL);
    assert(bytes == crypto_sign_PUBLICKEYBYTES);
    sodium_hex2bin(sig, crypto_sign_BYTES,
		   sig_hd, strlen(sig_hd),
		   " \r\n\t", &bytes, NULL);
    assert(bytes == crypto_sign_BYTES);
    int valid = crypto_sign_verify_detached(sig, msg, msg_len, pk);
    if(valid == 0) {
      puts("Signature verified");
      exit(EXIT_SUCCESS);
    }else{
      puts("Signature NOT verified");
      exit(EXIT_FAILURE);
    }
  }else{
    puts("Command not known");
    exit(EXIT_FAILURE);
  }
    exit(EXIT_FAILURE);
}
