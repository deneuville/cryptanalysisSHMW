#include "signature.h"
#include "parameters.h"
#include "rng.h"
#include "ffi_field.h"
#include "ffi_vec.h"

int main() {

  printf("\n");
  printf("M: %d   ", PARAM_M);
  printf("N: %d   ", PARAM_N);
  printf("W: %d   ", PARAM_W);
  printf("\n");


  unsigned char pk[PUBLIC_KEY_BYTES];
  unsigned char sk[SECRET_KEY_BYTES];

  unsigned char signature[SIGNATURE_BYTES];
  unsigned char *message;

  signature_keygen(pk, sk);

  printf("Secret key :\n");
  for(int i=0 ; i<SECRET_KEY_BYTES ; i++) printf("%.02X", sk[i]);
  printf("\n\n");

  printf("Public key :\n");
  for(int i=0 ; i<PUBLIC_KEY_BYTES ; i++) printf("%.02X", pk[i]);
  printf("\n\n");

  signature_sign(pk, message, signature);

  signature_verify(sk, message, signature);
}
