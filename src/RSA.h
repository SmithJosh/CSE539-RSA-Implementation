/*
 * RSA.h
 */

#ifndef RSA_H_
#define RSA_H_

/*
 * Data Types
 */

enum Version { two_prime, multi };

struct RSAPublicKey {
	long modulus;			// n
	long publicExponent;	// e
};

struct RSAPrivateKey {
	long modulus;			// n
	long privateExponent;	// d
};

struct PrivateKey {
	enum Version version;
	long modulus;			// n
	long publicExponent;	// e
	long privateExponent;	// d
	long prime1;			// p
	long prime2;			// q
	long exponent1;			// d mod (p-1)
	long exponent2;			// d mod (q-1)
	long coefficient;		// q^(-1) mod p
};

/*
 * Methods
 */

// Integer-to-Octet-String Primitive
unsigned char * I2OSP(unsigned long long x, unsigned int xLen);

// Octet-String-to-Integer Primitive
void OS2IP(unsigned char * X, unsigned long long * x);

unsigned long long modPow(unsigned long long base, unsigned long long exp, unsigned long long mod);

#endif /* RSA_H_ */
