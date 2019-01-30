#include "parameters.h"
#include "parsing.h"
#include "ffi_vec.h"

void sig_secret_key_to_string(unsigned char* skString, secretKey sk) {
	ffi_vec_to_string(skString, sk.E, PARAM_W);
	ffi_vec_to_string(skString + GF2MBYTES*PARAM_W, sk.x, PARAM_N);
	ffi_vec_to_string(skString + GF2MBYTES*(PARAM_W + PARAM_N), sk.y, PARAM_N);
}

void sig_secret_key_from_string(secretKey &sk, const unsigned char* skString) {

}

void sig_public_key_to_string(unsigned char* pkString, publicKey pk){
	ffi_vec_to_string(pkString, pk.h, PARAM_N);
	ffi_vec_to_string(pkString + GF2MBYTES * PARAM_N, pk.s, PARAM_N);
}

void sig_public_key_from_string(publicKey &pk, const unsigned char* pkString) {

}

void sig_signature_to_string(unsigned char* sigString, signature sig) {

}

void sig_signature_from_string(signature &sig, const unsigned char* sigString) {
	
}