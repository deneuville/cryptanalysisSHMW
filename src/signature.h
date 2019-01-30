#ifndef SIGNATURE_H
#define SIGNATURE_H

int signature_keygen(unsigned char *pk, unsigned char *sk);
int signature_sign(unsigned char *sk, unsigned char *m, unsigned int mlen, unsigned char *sig);
int signature_verify(unsigned char *pk, unsigned char *m, unsigned int mlen, unsigned char *sig);

#endif