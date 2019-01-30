#include "signature.h"
#include "parameters.h"
#include "signature_types.h"
#include "rng.h"
#include "ffi_field.h"
#include "ffi_elt.h"
#include "ffi_vec.h"
#include "parsing.h"

#include <fstream>
#include <errno.h>

using namespace std;

unsigned int secretSupport(ffi_vec &E, unsigned char* sig);

int main() {

  printf("Attack executable \n");
  printf("M: %d   ", PARAM_M);
  printf("N: %d   ", PARAM_N);
  printf("W: %d   ", PARAM_W);
  printf("\n");

  unsigned char pk[PUBLIC_KEY_BYTES];
  unsigned char sig[SIGNATURE_BYTES];

  //First load the signature
  ifstream sigFile;

  //Signature
  sigFile.open("files/sig", ios::binary);
  if(sigFile.is_open()) {
    sigFile.read((char*)sig, SIGNATURE_BYTES);
    sigFile.close();
  }
  else {
    cout << strerror(errno) << endl;
  }

  printf("Loaded signature :\n");
  for(int i=0 ; i<SIGNATURE_BYTES ; i++) printf("%.02X", sig[i]);
  printf("\n\n");

  ffi_vec E;

  unsigned int dimE = secretSupport(E, sig);

  printf("Recovered support : \n");
  ffi_vec_print(E, dimE);

  if(dimE == PARAM_W) {
    //Load the secret key and check if the recovered vector space E is the support of x and y
    ifstream skFile;
    unsigned char sk[PUBLIC_KEY_BYTES];
    //Secret key
    skFile.open("files/sk", ios::binary);
    if(skFile.is_open()) {
      skFile.read((char*)sk, SECRET_KEY_BYTES);
      skFile.close();
    }
    else {
      cout << strerror(errno) << endl;
    }

    secretKey sk_tmp;
    sig_secret_key_from_string(sk_tmp, sk);

    ffi_vec_echelonize(sk_tmp.E, PARAM_W);

    printf("Secret key support :\n");
    ffi_vec_print(sk_tmp.E, PARAM_W);

    if(ffi_vec_cmp(E, sk_tmp.E, PARAM_W)) printf("Secret support recovered\n");
  }
}

unsigned int secretSupport(ffi_vec &E, unsigned char* sig) {
  ffi_field_init();
  ffi_vec_init_mulmod();

  //First parse the signature
  signature sig_tmp;
  sig_signature_from_string(sig_tmp, sig);

  //Compute the support of g
  ffi_vec G;
  ffi_vec_set(G, sig_tmp.g, PARAM_N);
  unsigned int dimG = ffi_vec_gauss(G, PARAM_N);

  //Compute the support of u1
  ffi_vec U;
  ffi_vec_set(U, sig_tmp.u1, PARAM_N);
  unsigned int dimU = ffi_vec_gauss(U, PARAM_N);

  //Use techniques from the LRPC decoder to recover E, the support of x and y
  //Compute the spaces Ui = G[i]^-1 * U
  ffi_vec Ui[dimG];
  ffi_elt invG;
  for(unsigned int i = 0 ; i < dimG ; ++i) {
    ffi_elt_inv(invG, G[i]);
    ffi_vec_scalar_mul(Ui[i], U, invG, PARAM_N);
  }

  //Intersect until finding E
  unsigned int E_dim;
  ffi_vec_intersection(E, E_dim, Ui[0], PARAM_N, Ui[1], PARAM_N);

  if(E_dim > PARAM_W) {
    for(unsigned int i = 2 ; i < PARAM_W ; ++i) {
      ffi_vec_intersection(E, E_dim, E, E_dim, Ui[i], PARAM_N);
      if(E_dim <= PARAM_W) break;
    }
  }

  ffi_vec_echelonize(E, E_dim);

  return E_dim;
}