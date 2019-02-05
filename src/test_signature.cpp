#include "signature.h"
#include "parameters.h"
#include "rng.h"
#include "ffi_field.h"
#include "ffi_vec.h"

#include <fstream>
#include <errno.h>

#define ITERATIONS 1
#define VERBOSE 1

using namespace std;

int main() {

  printf("\n");
  printf("M: %d   ", PARAM_M);
  printf("N: %d   ", PARAM_N);
  printf("W: %d   ", PARAM_W);
  printf("\n");


  for(int iter=0 ; iter<ITERATIONS ; iter++) {
    unsigned char pk[PUBLIC_KEY_BYTES];
    unsigned char sk[SECRET_KEY_BYTES];

    unsigned char signature[SIGNATURE_BYTES];

    unsigned int mlen = 4;
    const char *tmp = "toto";
    unsigned char *message = (unsigned char *) malloc(mlen * sizeof(char));
    memcpy(message, tmp, mlen);

    /***************** Keygen ********************/

    signature_keygen(pk, sk);

    if(VERBOSE) {
      printf("Secret key :\n");
      for(int i=0 ; i<SECRET_KEY_BYTES ; i++) printf("%.02X", sk[i]);
      printf("\n\n");

      printf("Public key :\n");
      for(int i=0 ; i<PUBLIC_KEY_BYTES ; i++) printf("%.02X", pk[i]);
      printf("\n\n");
    }

    /************* Signature ********************/

    signature_sign(sk, message, mlen, signature);

    if(VERBOSE) {
      printf("Message :\n");
      for(int i=0 ; i<mlen ; i++) printf("%c", message[i]);
      printf("\n\n");

      printf("Signature :\n");
      for(int i=0 ; i<SIGNATURE_BYTES ; i++) printf("%.02X", signature[i]);
      printf("\n\n");   
    }
    
    /************* Verification ****************/

    if(VERBOSE) {
      if(!signature_verify(pk, message, mlen, signature)) printf("Signature OK\n");
      else printf("Error during verification\n");
    }
      
    //Stores the keys and the signature in the files/ folder to perform the attack
    ofstream pkFile, skFile, sigFile;

    char pkFilename[50], skFilename[50], sigFilename[50];

    sprintf(pkFilename, "files/pk%d", iter);
    sprintf(skFilename, "files/sk%d", iter);
    sprintf(sigFilename, "files/sig%d", iter);

    //Public key
    pkFile.open(pkFilename);
    if(pkFile.is_open()) {
      for(int i=0 ; i<PUBLIC_KEY_BYTES ; i++) pkFile << pk[i];
      pkFile.close();
    }
    else {
      cout << strerror(errno) << endl;
    }

    //Secret key
    skFile.open(skFilename);
    if(skFile.is_open()) {
      for(int i=0 ; i<SECRET_KEY_BYTES ; i++) skFile << sk[i];
      pkFile.close();
    }
    else {
      cout << strerror(errno) << endl;
    }

    //Signature
    sigFile.open(sigFilename);
    if(sigFile.is_open()) {
      for(int i=0 ; i<SIGNATURE_BYTES ; i++) sigFile << signature[i];
      pkFile.close();
    }
    else {
      cout << strerror(errno) << endl;
    }

    free(message);
  }
}
