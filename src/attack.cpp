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
#include <time.h>

#include <NTL/GF2.h>
#include <NTL/vec_GF2.h>
#include <NTL/mat_GF2E.h>
#include <NTL/mat_GF2.h>

#define ITERATIONS 1
#define VERBOSE 1

using namespace std;
using namespace NTL;

unsigned int secretSupport(ffi_vec &E, unsigned char* sig);
long gaussWithEq(mat_GF2& M, vec_GF2 &equations);
vec_GF2 coordsFromVEc(ffi_vec x, ffi_vec support);
unsigned int solveSystem(ffi_vec &x, ffi_vec &y, const ffi_vec &E, unsigned char *pk);

int main() {

  printf("Attack executable \n");
  printf("M: %d   ", PARAM_M);
  printf("N: %d   ", PARAM_N);
  printf("W: %d   ", PARAM_W);
  printf("\n");

  int recoveredSK = 0;
  float totalTime = 0;

  for(int iter=0 ; iter<ITERATIONS ; iter++) {
    char pkFilename[50],  sigFilename[50];

    sprintf(pkFilename, "files/pk%d", iter);
    sprintf(sigFilename, "files/sig%d", iter);

    unsigned char pk[PUBLIC_KEY_BYTES];
    unsigned char sig[SIGNATURE_BYTES];

    //First load the signature and the public key
    ifstream sigFile, pkFile;

    //Signature
    sigFile.open(sigFilename, ios::binary);
    if(sigFile.is_open()) {
      sigFile.read((char*)sig, SIGNATURE_BYTES);
      sigFile.close();
    }
    else {
      cout << strerror(errno) << endl;
    }

    //Public key
    pkFile.open(pkFilename, ios::binary);
    if(pkFile.is_open()) {
      pkFile.read((char*)pk, PUBLIC_KEY_BYTES);
      pkFile.close();
    }
    else {
      cout << strerror(errno) << endl;
    }

    if(VERBOSE) {
      printf("Loaded public key :\n");
      for(int i=0 ; i<PUBLIC_KEY_BYTES ; i++) printf("%.02X", pk[i]);
      printf("\n\n");  

      printf("Loaded signature :\n");
      for(int i=0 ; i<SIGNATURE_BYTES ; i++) printf("%.02X", sig[i]);
      printf("\n\n");
    }
    
    ffi_vec E;

    clock_t begin, end;
    begin = clock();

    //Recover the support of x and y
    unsigned int dimE = secretSupport(E, sig);

    if(VERBOSE) {
      printf("Recovered support : \n");
      ffi_vec_print(E, dimE);
    }

    if(dimE == PARAM_W) {
      //Load the secret key and check if the recovered vector space E is the support of x and y
      ifstream skFile;

      //Then solve a linear system to compute x and y
      ffi_vec x, y;
      solveSystem(x, y, E, pk);

      publicKey pk_tmp;
      sig_public_key_from_string(pk_tmp, pk);

      //Check validity of the recovered 
      ffi_vec tmp;
      ffi_vec computedS;
      ffi_vec_mul(tmp, pk_tmp.h, y, PARAM_N);

      ffi_vec_add(computedS, x, tmp, PARAM_N);

      if(ffi_vec_cmp(computedS, pk_tmp.s, PARAM_N)) {
        recoveredSK++;
        end = clock();
        totalTime += (float)(end-begin)/CLOCKS_PER_SEC;
      }

      if(VERBOSE) {
        if(ffi_vec_cmp(computedS, pk_tmp.s, PARAM_N)) printf ("Successfully recovered x and y such that x + hy = s\n");
        else printf("Faild to recover x and y such that x + hy = s\n");
      }
    }
  }

  printf("%d secret keys recovered out of %d\n", recoveredSK, ITERATIONS);
  printf("Average recovery time : %fs\n", totalTime/recoveredSK);
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
    ffi_vec_scalar_mul(Ui[i], U, invG, dimU);
  }

  //Intersect until finding E
  unsigned int E_dim;
  ffi_vec_intersection(E, E_dim, Ui[0], dimU, Ui[1], dimU);

  if(E_dim > PARAM_W) {
    for(unsigned int i = 2 ; i < PARAM_W ; ++i) {
      ffi_vec_intersection(E, E_dim, E, E_dim, Ui[i], dimU);
      if(E_dim <= PARAM_W) break;
    }
  }

  return E_dim;
}

long gaussWithEq(mat_GF2& M, vec_GF2 &equations)
{
   long i, j;
   long pivot;

   long n = M.NumRows();
   long m = M.NumCols();

   for(i=0 ; i<m ; i++) {
    //Look for a valid pivot
    pivot = -1;

    for(j=i ; j<n ; j++) {
      if(M[j][i] == 1) {
        pivot = j;
        break;
      }
    }

    if(pivot == -1) return 1;
   
    if(pivot != i) {
      //Swap the pivot with the ith line
      vec_GF2 vecTmp;
      GF2 tmp;

      /**** Swap ****/
      vecTmp = M[i];
      tmp = equations[i];
      M[i] = M[pivot];
      equations[i] = equations[pivot];
      M[pivot] = vecTmp;
      equations[pivot] = tmp;
      /**************/
    }

    //Add this line to the lines below
    for(j= i+1 ; j<n ; j++) {
      if(M[j][i] == 1) {
        M[j] += M[i];
        equations[j] += equations[i];
      }
    }
   }

   return 0;
}

vec_GF2 coordsFromVEc(ffi_vec x, ffi_vec support) {
  vec_GF2 res;
  res.SetLength(PARAM_N * PARAM_W);
  //Build the system
  mat_GF2 system;
  system.SetDims(PARAM_W, PARAM_W);

  for(int i=0 ; i<PARAM_W ; i++) {
    for(int j=0 ; j<PARAM_W ; j++) {
      system[j][i] = coeff(rep(support[j]), i+1);
    }
  }

  //Solve for each coordinate of x
  for(int i=0 ; i<PARAM_N ; i++) {
    vec_GF2 equations;
    equations.SetLength(PARAM_W);

    for(int j=0 ; j<PARAM_W ; j++) equations[j] = coeff(rep(x[i]), j+1);

    vec_GF2 solutions;
    GF2 det;

    solve(det, solutions, system, equations);

    for(int j=0 ; j<PARAM_W ; j++) res[i*PARAM_W + j] = solutions[j];
  }

  return res;
}

unsigned int solveSystem(ffi_vec &x, ffi_vec &y, const ffi_vec &E, unsigned char *pk) {
  //Parse the public key to recover h
  publicKey pk_tmp;
  sig_public_key_from_string(pk_tmp, pk);

  //Build the matrix  H = I | rot(h)
  mat_GF2E H;
  H.SetDims(PARAM_N, 2*PARAM_N);
  //Left part
  for(int i=0 ; i<PARAM_N ; i++) {
    H[i][i] = 1;
  }
  
  //Right part
  //First row
  H[0][PARAM_N] = pk_tmp.h[0];
  for(int i=1 ; i<PARAM_N ; i++) {
    H[0][i+PARAM_N] = pk_tmp.h[PARAM_N - i];
  }

  //Other rows
  for(int row=1 ; row<PARAM_N ; row++) {
    for(int col=0 ; col<PARAM_N ; col++) {
      if (col != 0) H[row][col + PARAM_N] = H[row-1][col-1 + PARAM_N];
      else H[row][PARAM_N] = H[row-1][2 * PARAM_N - 1];
    }
  }

  //Unfold the error vector
  mat_GF2E Hprime;
  Hprime.SetDims(PARAM_N, 2*PARAM_N*PARAM_W);

  for(int row=0 ; row<PARAM_N ; row++) {
    for(int col=0 ; col<2*PARAM_N ; col++) {
       for(int b=0 ; b<PARAM_W ; b++) {
         Hprime[row][col*PARAM_W + b] = H[row][col] * E[b];
       }
    }
  }

  //Unfold this matrix in F2
  mat_GF2 system;
  system.SetDims(PARAM_N * PARAM_M, 2*PARAM_N*PARAM_W);

  for(int row=0 ; row < PARAM_N ; row++) {
    for(int col=0 ; col < 2*PARAM_N*PARAM_W ; col++) {
      for(int j=0 ; j<PARAM_M ; j++) {
        system[row*PARAM_M + j][col] = coeff(rep(Hprime[row][col]), j);
      }
    }
  }

  //Unfold s the same way to obtain nm equations in the base field
  vec_GF2 equations;
  equations.SetLength(PARAM_N * PARAM_M);

  for(int i=0 ; i<PARAM_N ; i++) {
    for(int j=0 ; j<PARAM_M ; j++) {
      equations[i*PARAM_M + j] = coeff(rep(pk_tmp.s[i]), j);
    }
  }

  //gaussWithEq(system, equations);
  //Take a square submatrix
  //We need to find a subset of lines of the system s.t the square matrix is full-rank
  
  mat_GF2 subsystem;
  vec_GF2 subequations;
  subsystem.SetDims(2*PARAM_N*PARAM_W, 2*PARAM_N*PARAM_W);
  subequations.SetLength(2*PARAM_N*PARAM_W);

  gaussWithEq(system, equations);

  for(int i=0 ; i<2*PARAM_N*PARAM_W ; i++) {
    for(int j=0 ; j<2*PARAM_N*PARAM_W ; j++) {
      subsystem[i][j] = system[i][j];
    }
    subequations[i] = equations[i];
  }

  vec_GF2 solution;
  GF2 det;
  solve(det, subsystem, solution, subequations);

  //The solution are stored in the equations vector that has been modified by gauss
  x.SetLength(PARAM_N);
  y.SetLength(PARAM_N);

  for(int i=0 ; i<PARAM_N ; i++) {
    for(int j=0 ; j<PARAM_W ; j++) {
      x[i] = x[i] + E[j] * solution[i*PARAM_W + j];
      y[i] = y[i] + E[j] * solution[(i+PARAM_N)*PARAM_W + j];
    }
  }

  return 0;
}
