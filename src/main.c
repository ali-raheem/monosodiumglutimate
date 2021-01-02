#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>
#include <assert.h>

#define VERSION "v0.0.1"
#define PUBLICKEYPATH "signing.pub"
#define SECRETKEYPATH "signing.prv"

void usage(char *name) {
  printf("Signing:\n%s MESSAGE\n", name);
  printf("e.g.\n%s \"Hello, World!\"\n\n", name);
  printf("Verifying:\n%s MESSAGE SIGNATURE PUBLICKEY\n", name);
  printf("e.g.\n%s \"Hello, world!\" Xiu1bFiOFvdDABj8P5MmoksL/zZdoETGzfl+J/X+Fumu5mdMFHIG440QVAqtV3a+GRNN7VFEgOXfgQNQsEutDA fU/io6ZMaeDc8VdSI7XULxfqmF6oqPmQVNFQqrn1IqA\n\n", name);

  exit(EXIT_FAILURE);
}

int load_keys(unsigned char* pk, unsigned char* sk) {
  //  puts("Attempting to load keys...");
  const size_t pk_b64_len = sodium_base64_encoded_len(crypto_sign_PUBLICKEYBYTES, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
  char *pk_b64 = (char *) malloc(pk_b64_len);
  const size_t sk_b64_len = sodium_base64_encoded_len(crypto_sign_SECRETKEYBYTES, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
  char *sk_b64 = (char *) malloc(sk_b64_len);
  FILE* fp;
  fp = fopen(PUBLICKEYPATH, "r");
  if (NULL == fp) return -1;
  if (pk_b64_len != fread(pk_b64, 1, pk_b64_len, fp)) return -1;
  fclose(fp);
  size_t pk_len = crypto_sign_PUBLICKEYBYTES;
  sodium_base642bin(pk, crypto_sign_PUBLICKEYBYTES, pk_b64, pk_b64_len, " \n\t\r", &pk_len, NULL, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
  fp = fopen(SECRETKEYPATH, "r");
  if (NULL == fp) return -1;
  if (sk_b64_len != fread(sk_b64, 1, sk_b64_len, fp)) return -1;
  fclose(fp);
  size_t sk_len = crypto_sign_SECRETKEYBYTES;
  sodium_base642bin(sk, crypto_sign_SECRETKEYBYTES, sk_b64, sk_b64_len, " \n\t\r", &sk_len, NULL, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);

  free(pk_b64);
  free(sk_b64);
  if (pk_len == crypto_sign_PUBLICKEYBYTES &&
      sk_len == crypto_sign_SECRETKEYBYTES)
    return 0;

  return -1;
}

int save_keys(unsigned char* pk, unsigned char* sk) {
  const size_t pk_b64_len = sodium_base64_encoded_len(crypto_sign_PUBLICKEYBYTES, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
  char *pk_b64 = (char *) malloc(pk_b64_len);
  assert(NULL != pk_b64);
  pk_b64 = sodium_bin2base64(pk_b64, pk_b64_len, pk, crypto_sign_PUBLICKEYBYTES,  sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
  printf("Public key: %s\n", pk_b64);
  
  const size_t sk_b64_len = sodium_base64_encoded_len(crypto_sign_SECRETKEYBYTES, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
  char *sk_b64 = (char *) malloc(sk_b64_len);
  assert(NULL != sk_b64);
  sk_b64 = sodium_bin2base64(sk_b64, sk_b64_len, sk, crypto_sign_SECRETKEYBYTES, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);

  FILE *fp;
  fp = fopen(PUBLICKEYPATH, "w");
  assert(NULL != fp);
  fwrite(pk_b64, 1, pk_b64_len, fp);
  fclose(fp);
  
  fp = fopen(SECRETKEYPATH, "w");
  assert(NULL != fp);
  fwrite(sk_b64, 1, sk_b64_len, fp);
  fclose(fp);
  free(pk_b64);
  free(sk_b64);
}

char *sign_msg(const char *msg, const size_t msg_len, char *sig_b64, const unsigned char *sk) {
  crypto_sign_state state;
  unsigned char sig[crypto_sign_BYTES];
  crypto_sign_init(&state);
  crypto_sign_update(&state, msg, msg_len);
  crypto_sign_final_create(&state, sig, NULL, sk);
  
  const size_t sig_b64_len = sodium_base64_encoded_len(crypto_sign_BYTES, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
  sig_b64 = (char *) malloc(sig_b64_len);
  assert(NULL != sig_b64);
  sodium_bin2base64(sig_b64, sig_b64_len, sig, crypto_sign_BYTES, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
  
  return sig_b64;
}

int verify_msg(const char* msg, const size_t msg_len, const char* sig_b64, const size_t sig_b64_len, const unsigned char *pk){
  //  const size_t msg_len = strlen(msg);  
  crypto_sign_state state;
  unsigned char sig[crypto_sign_BYTES];
  size_t sig_len;
  sodium_base642bin(sig, crypto_sign_BYTES, sig_b64, sig_b64_len, " \n\t\r", &sig_len, NULL, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
  if(sig_len != crypto_sign_BYTES){
    puts("Could not parse signature");
    return -1;
  }
  crypto_sign_init(&state);
  crypto_sign_update(&state, msg, msg_len);
  return crypto_sign_final_verify(&state, sig, pk);
}  

int main(int argc, char *argv[]) {
  if(argc != 2 && argc != 4) {
    usage(argv[0]);
    exit(EXIT_FAILURE);
  }
  assert(sodium_init() >= 0);
  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];
  char *msg = argv[1];
  const size_t msg_len = strlen(msg);
  char *sig;
  if(argc == 2) {
    if(0 != load_keys(pk, sk)) {
      crypto_sign_keypair(pk, sk);
      save_keys(pk, sk);
    }
    sig = sign_msg(msg, msg_len, sig, sk);
    assert(NULL != sig);
    puts(sig);
    free(sig);
    exit(EXIT_SUCCESS);
  }else{
    sig = argv[2];
    char *pk_b64 = argv[3];
    const size_t pk_b64_len = strlen(pk_b64);
    size_t pk_len = crypto_sign_PUBLICKEYBYTES;
    sodium_base642bin(pk, crypto_sign_PUBLICKEYBYTES, pk_b64, pk_b64_len, " \n\t\r", &pk_len, NULL, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
    size_t sig_len = strlen(sig);
    if (0 == verify_msg(msg, msg_len, sig, sig_len, pk)) {
      puts("Verification successful");
      exit(EXIT_SUCCESS);
    }else{
      puts("Verification failed");
      exit(EXIT_FAILURE);
    }
  }
}
