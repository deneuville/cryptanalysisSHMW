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

  signature_sign(pk, message, signature);

  signature_verify(sk, message, signature);
}
