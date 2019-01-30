#ifndef PARSING_H
#define PARSING_H

#include "ffi_vec.h"
#include "signature_types.h"

void sig_secret_key_to_string(unsigned char* skString, secretKey sk);
void sig_secret_key_from_string(secretKey &sk, const unsigned char* skString);

void sig_public_key_to_string(unsigned char* pkString, publicKey pk);
void sig_public_key_from_string(publicKey &pk, const unsigned char* pkString);

void sig_signature_to_string(unsigned char* sigString, signature sig);
void sig_signature_from_string(signature &sig, const unsigned char* sigString);

#endif

