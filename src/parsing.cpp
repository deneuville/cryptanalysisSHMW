#include "parameters.h"
#include "parsing.h"
#include "ffi_vec.h"

void sig_secret_key_to_string(unsigned char* skString, secretKey sk) {
	ffi_vec_to_string(skString, sk.E, PARAM_W);
	ffi_vec_to_string(skString + GF2MBYTES*PARAM_W, sk.x, PARAM_N);
	ffi_vec_to_string(skString + GF2MBYTES*(PARAM_W + PARAM_N), sk.y, PARAM_N);
	ffi_vec_to_string(skString + GF2MBYTES*(PARAM_W + 2*PARAM_N), sk.h, PARAM_N);
}

void sig_secret_key_from_string(secretKey &sk, const unsigned char* skString) {
	ffi_vec_from_string(sk.E, PARAM_W, skString);
	ffi_vec_from_string(sk.x, PARAM_N, skString + GF2MBYTES*PARAM_W);
	ffi_vec_from_string(sk.y, PARAM_N, skString + GF2MBYTES*(PARAM_W + PARAM_N));
	ffi_vec_from_string(sk.h, PARAM_N, skString + GF2MBYTES*(PARAM_W + 2*PARAM_N));
}

void sig_public_key_to_string(unsigned char* pkString, publicKey pk){
	ffi_vec_to_string(pkString, pk.h, PARAM_N);
	ffi_vec_to_string(pkString + GF2MBYTES * PARAM_N, pk.s, PARAM_N);
}

void sig_public_key_from_string(publicKey &pk, const unsigned char* pkString) {
	ffi_vec_from_string(pk.h, PARAM_N, pkString);
	ffi_vec_from_string(pk.s, PARAM_N, pkString + GF2MBYTES * PARAM_N);
}

void sig_signature_to_string(unsigned char* sigString, signature sig) {
	ffi_vec_to_string(sigString, sig.g, PARAM_N);
	ffi_vec_to_string(sigString + GF2MBYTES*PARAM_N, sig.u1, PARAM_N);
	ffi_vec_to_string(sigString + GF2MBYTES*2*PARAM_N, sig.u2, PARAM_N);
}

void sig_signature_from_string(signature &sig, const unsigned char* sigString) {
	ffi_vec_from_string(sig.g, PARAM_N, sigString);
	ffi_vec_from_string(sig.u1, PARAM_N, sigString + GF2MBYTES*PARAM_N);
	ffi_vec_from_string(sig.u2, PARAM_N, sigString + GF2MBYTES*2*PARAM_N);
}