#include "hash.h"
#include "rng.h"
#include "parsing.h"
#include "signature.h"
#include "signature_types.h"
#include "parameters.h"
#include "ffi_field.h"
#include "ffi_vec.h"

/*
Implementation of H
We chose the following hash function :
First concatenate a string representing I and the message m
Compute a SHA512 of this new message
Use this hash to seed a seedexpander used to generate g

Note that the choice of H has no importance for the attack
*/
void H(ffi_vec &g, const ffi_vec& I, unsigned char* m, int mlen) {
	//String prepare
	unsigned char stringToHash[GF2MBYTES * PARAM_N + mlen];
	ffi_vec_to_string(stringToHash, I, PARAM_N);
	memcpy(stringToHash + GF2MBYTES*PARAM_N, m, mlen);

	//Hash
	unsigned char hash[SHA512_BYTES];
	sha512(hash, stringToHash, GF2MBYTES * PARAM_N + mlen);

	//Creation of the seedexpander
	AES_XOF_struct* sk_seedexpander = (AES_XOF_struct*) malloc(sizeof(AES_XOF_struct));
	seedexpander_init(sk_seedexpander, hash, hash + 32, SEEDEXPANDER_MAX_LENGTH);

	//Choice of G, the support of g
	ffi_vec G;
	ffi_vec_set_random_full_rank_using_seedexpander(G, PARAM_W, sk_seedexpander);

	//Choice of g
	ffi_vec_set_random_from_support_using_seedexpander(g, PARAM_N, G, PARAM_W, sk_seedexpander);

	free(sk_seedexpander);
}

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
	//h is needed in the secret key to sign
	ffi_vec_set(sk_tmp.h, pk_tmp.h, PARAM_N);

	//Computation of s = x + h.y
	ffi_vec tmp;
	ffi_vec_mul(tmp, pk_tmp.h, sk_tmp.y, PARAM_N);

	ffi_vec_add(pk_tmp.s, sk_tmp.x, tmp, PARAM_N);

	//Parsing
	sig_secret_key_to_string(sk, sk_tmp);
	sig_public_key_to_string(pk, pk_tmp);

	return 0;
}

int signature_sign(unsigned char *sk, unsigned char *m, unsigned int mlen, unsigned char *sig) {
	ffi_field_init();
	ffi_vec_init_mulmod();

	//Recover public key from the string
	secretKey sk_tmp;

	sig_secret_key_from_string(sk_tmp, sk);

	//Choice of R, the support of r1 and r2
	ffi_vec R, r1, r2;
	ffi_vec_set_random_full_rank_using_rng(R, PARAM_W);

	//Choice of r1 and r2
	ffi_vec_set_random_from_support_using_rng(r1, PARAM_N, R, PARAM_W);
	ffi_vec_set_random_from_support_using_rng(r2, PARAM_N, R, PARAM_W);

	//Computation of I = r1 + h.r2
	ffi_vec I, tmp;
	ffi_vec_mul(tmp, sk_tmp.h, r2, PARAM_N);

	ffi_vec_add(I, r1, tmp, PARAM_N);

	signature sig_tmp;

	//Computation of g = H(I, m)
	H(sig_tmp.g, I, m, mlen);

	//Computation of u1 = xg + r1
	ffi_vec_mul(tmp, sk_tmp.x, sig_tmp.g, PARAM_N);
	ffi_vec_add(sig_tmp.u1, tmp, r1, PARAM_N);

	//Computation of u2 = yg + r2
	ffi_vec_mul(tmp, sk_tmp.y, sig_tmp.g, PARAM_N);
	ffi_vec_add(sig_tmp.u2, tmp, r2, PARAM_N);

	//Parsing
	sig_signature_to_string(sig, sig_tmp);

	return 0;
}

int signature_verify(unsigned char *pk, unsigned char *m, unsigned int mlen, unsigned char *sig) {
	ffi_field_init();
	ffi_vec_init_mulmod();

	return 0;
}