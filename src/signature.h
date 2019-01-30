#ifndef SIGNATURE_H
#define SIGNATURE_H

int signature_keygen(unsigned char *pk, unsigned char *sk);
int signature_sign(unsigned char *pk, unsigned char *m, unsigned char *sig);
int signature_verify(unsigned char *sk, unsigned char *m, unsigned char *sig);

#endif