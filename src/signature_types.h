#ifndef SIG_TYPES_H
#define SIG_TYPES_H

#include "ffi_vec.h"

typedef struct secretKey {
	ffi_vec E;
	ffi_vec x;
	ffi_vec y;
	ffi_vec h;
} secretKey;

typedef struct publicKey {
	ffi_vec h;
	ffi_vec s;
} publicKey;

typedef struct signature {
	ffi_vec g;
	ffi_vec u1;
	ffi_vec u2;
} signature;

#endif
