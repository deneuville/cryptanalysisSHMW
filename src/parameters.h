#ifndef SIG_PARAMETER_H
#define SIG_PARAMETER_H

#define PARAM_M 89 /**< Parameter m of the scheme (finite field GF(2^m)) */
#define PARAM_N 67 /**< Parameter n of the scheme (code length) */
#define PARAM_W 5 /**< Parameter d of the scheme (weight of vectors) */

#define GF2MBYTES 12 //Number of bytes to store an element of GF2^m

#define SHA512_BYTES 64 /**< Size of SHA512 output */

#define SEEDEXPANDER_SEED_BYTES 40 /**< Seed size of the NIST seed expander */
#define SEEDEXPANDER_MAX_LENGTH 4294967295 /**< Max length of the NIST seed expander */

//Size of the keys and signature - not tight
#define SECRET_KEY_BYTES 1668
#define PUBLIC_KEY_BYTES 1608
#define SIGNATURE_BYTES 2412

#endif
