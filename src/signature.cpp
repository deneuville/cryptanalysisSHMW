#include "hash.h"
#include "rng.h"
#include "parsing.h"
#include "signature.h"
#include "signature_types.h"
#include "parameters.h"
#include "ffi_field.h"
#include "ffi_vec.h"


int signature_keygen(unsigned char *pk, unsigned char *sk) {
	ffi_field_init();
	ffi_vec_init_mulmod();

	publicKey pk_tmp;
	secretKey sk_tmp;

	//Choice of the secret support (noted E) of x and y
	ffi_vec_set_random_full_rank_using_rng(sk_tmp.E, PARAM_W);

	//Choice of x and y
	ffi_vec_set_random_from_support_using_rng(sk_tmp.x, PARAM_N, sk_tmp.E, PARAM_W);
	ffi_vec_set_random_from_support_using_rng(sk_tmp.y, PARAM_N, sk_tmp.E, PARAM_W);

	//Choice of h
	ffi_vec_set_random_full_rank_using_rng(pk_tmp.h, PARAM_N);

	//Computation of s = x + h.y
	ffi_vec tmp;
	ffi_vec_mul(tmp, pk_tmp.h, sk_tmp.y, PARAM_N);

	ffi_vec_add(pk_tmp.s, sk_tmp.x, tmp, PARAM_N);

	//Parsing
	sig_secret_key_to_string(sk, sk_tmp);
	sig_public_key_to_string(pk, pk_tmp);
}

int signature_sign(unsigned char *pk, unsigned char *m, unsigned char *sig) {
	ffi_field_init();
	ffi_vec_init_mulmod();
}

int signature_verify(unsigned char *sk, unsigned char *m, unsigned char *sig) {
	ffi_field_init();
	ffi_vec_init_mulmod();
}