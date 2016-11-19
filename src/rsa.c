#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <gmp.h>
#include "rsa.h"

// Convert nonnegative integer x to an octet string
char* I2OSP(mpz_t x, int xLen) {
	size_t digits = mpz_sizeinbase(x, 16);
	if (xLen * 2 < digits) {
		printf("Integer too large");
		return NULL;
	}
	char *str = calloc(xLen * 2 + 1, sizeof(char));
	return mpz_get_str(str, 16, x);
}

// Convert octet string to a nonnegative integer
void OS2IP(char *X, mpz_t x) {
	mpz_set_str(x, X, 16);
}

// RSA Encryption Primative
void RSAEP(struct RSAPublicKey *K, mpz_t m, mpz_t c) {
	mpz_powm_sec(c, m, K->publicExponent, K->modulus);
}

// RSA Decryption Primative
void RSADP(struct RSAPrivateKey *K, mpz_t c, mpz_t m) {
	mpz_powm_sec(m, c, K->privateExponent, K->modulus);
}

int main() {		
	struct RSAPublicKey pubK;
	struct RSAPrivateKey privK;
	mpz_t mod, e, d, m, c;

	mpz_init(mod); mpz_init(e); mpz_init(d);
	mpz_init(m); mpz_init(c);

	OS2IP("8c 69 50", mod);
	mpz_set(pubK.modulus, mod);
	mpz_set(privK.modulus, mod);
	mpz_set_str(pubK.publicExponent, "01 00 01", 16);

	gmp_printf ("%Zd\n", mod);

	//RSAEP(&K_pub, m, c);
	//RSADP(&K_priv, c, m);
	return 0;
}
