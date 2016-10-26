/*
 ============================================================================
 Name        : RSA.c
 Description : Implementation of the RSA encryption scheme
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include "RSA.h"

int main(void) {
	return EXIT_SUCCESS;
}

// RSA Encryption Primative. Assumes that RSA Public Key is valid.
unsigned long long RSAEP(struct RSAPublicKey * pubKey, unsigned long long m) {

	// Step 1
	if (m >= pubKey->modulus) {
		puts("Error: message representative out of range");
		return 0;
	}

	// Steps 2 & 3
	return modPow(m, pubKey->publicExponent, pubKey->modulus);
}

// RSA Decryption Primative. Assumes RSA Private Key is valid.
unsigned long long RSADP(struct RSAPrivateKey * privKey, unsigned long long c) {

	// Step 1
	if (c >= privKey->modulus) {
		puts("Error: ciphertext representative out of range");
		return 0;
	}

	// Steps 2 & 3
	return modPow(c, privKey->privateExponent, privKey->modulus);
}

// Integer-to-Octet-String Primitive
unsigned char * I2OSP(unsigned long long x, unsigned int xLen) {
	unsigned char * X = malloc((1 + xLen) * sizeof(unsigned char));

	// Step 1
	if ((x >> (xLen * 8)) & 1) {
		puts("Error: integer too large");
		return NULL;
	}

	// Step 2
	int i = xLen;
	while (i-- > 0) {
		X[i] = x & 0xFF;
		x >>= 8;
	}

	// Step 3
	X[xLen] = '\0';
	return X;
}

// Octet-String-to_Integer Primitive
void OS2IP(unsigned char * X, unsigned long long * x) {

	int i;
	unsigned long long out = 0;
	for (i = 0; X[i] != '\0'; ++i)
		out = (out << 8) | X[i];

	*x = out;
	return;
}

// Computes base^exp % mod using successive squaring.
unsigned long long modPow(unsigned long long base, unsigned long long exp, unsigned long long mod) {
	unsigned long long out = 1;

	while (exp > 0) {
		if ((exp & 1) == 1)
			out = (int)((out * base) % mod);
		exp >>= 1;
		base = (base * base) % mod;
	}

	return out;
}
