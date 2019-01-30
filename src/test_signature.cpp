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

  unsigned int mlen = 4;
  const char *tmp = "toto";
  unsigned char *message = (unsigned char *) malloc(mlen * sizeof(char));
  memcpy(message, tmp, mlen);

  /***************** Keygen ********************/

  signature_keygen(pk, sk);

  printf("Secret key :\n");
  for(int i=0 ; i<SECRET_KEY_BYTES ; i++) printf("%.02X", sk[i]);
  printf("\n\n");

  printf("Public key :\n");
  for(int i=0 ; i<PUBLIC_KEY_BYTES ; i++) printf("%.02X", pk[i]);
  printf("\n\n");

  /************* Signature ********************/

  signature_sign(sk, message, mlen, signature);

  printf("Message :\n");
  for(int i=0 ; i<mlen ; i++) printf("%c", message[i]);
  printf("\n\n");

  printf("Signature :\n");
  for(int i=0 ; i<SIGNATURE_BYTES ; i++) printf("%.02X", signature[i]);
  printf("\n\n");
  
  /************* Verification ****************/

  if(!signature_verify(pk, message, mlen, signature)) printf("Signature OK\n");
  else printf("Error during verification\n");

  free(message);
}
