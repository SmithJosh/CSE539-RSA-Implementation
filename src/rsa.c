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

// Determine whether n is prime. Return 2 is definitely prime, 1 if probably prime, 0 if non-prime.
// Uses Miller-Rabin primality tests. Use reps between 15-50.
int mpz_probab_prime_p(const mpz_t n, int reps);

// Generate RSA modulus using two odd primes for now. Miller Rabin only set to 15. Specify number of bits
// Also, this is deterministic at the moment. Will change later...
void gen_modulus(mpz_t n, mpz_t r1, mpz_t r2, int bits) {
    printf("%s\n", "Generating primes...");
    gmp_randstate_t t;
    gmp_randinit_mt(t);

    while (mpz_probab_prime_p(r1, 15) != 2) {
        mpz_rrandomb(r1, t, bits/2);
    }
    while (mpz_probab_prime_p(r2, 15) != 2) {
        mpz_rrandomb(r2, t, bits/2);
    }

    mpz_mul(n, r1, r2);

    gmp_printf("%s%Zd\n", "RSA modulus: ", n);
}

void gen_e(mpz_t e, mpz_t n, mpz_t r1, mpz_t r2) {
    // r1m1 stands for r1-1, etc.
    printf("%s\n", "Generating public exponent e...");
    mpz_t lambda, gcd, one, r1m1, r2m1, nm1;
    mpz_init(lambda); mpz_init(gcd); mpz_init(one); mpz_init(r1m1); mpz_init(r2m1); mpz_init(nm1);

    unsigned long int uno = 1;
    mpz_set_ui(one, uno);
    mpz_sub(r1m1, r1, one);
    mpz_sub(r2m1, r1, one);
    mpz_sub(nm1, n, one);
    mpz_lcm(lambda, r1m1, r2m1);

    gmp_randstate_t t;
    gmp_randinit_mt(t);
    while (mpz_cmp(gcd, one) != 0) {
        mpz_urandomm(e, t, nm1); // This generates random numbers between 0 and n-1. We want between 3 and n-1. Knock on wood.
        mpz_gcd(gcd, e, lambda);
    }
   
    gmp_printf("%s%Zd\n", "Public exponent e: ", e);
}

// Generate random number w/ length n
void mpz_rrandomb(mpz_t rop, gmp_randstate_t state, mp_bitcnt_t n);

// Sets rop to GCD of op1 and op2
void mpz_gcd(mpz_t rop, const mpz_t op1, const mpz_t op2);

int main() {		
	struct RSAPublicKey pubK;
	struct RSAPrivateKey privK;
	mpz_t mod, e, d, m, c, r1, r2;
    mpz_init(mod); mpz_init(e); mpz_init(d); mpz_init(r1); mpz_init(r2);
	mpz_init(m); mpz_init(c);
 
    gen_modulus(mod, r1, r2, 20);
    gen_e(e, mod, r1, r2);

	OS2IP("8c 69 50", mod);
	mpz_set(pubK.modulus, mod);
	mpz_set(privK.modulus, mod);
	mpz_set_str(pubK.publicExponent, "01 00 01", 16);

    gmp_printf("%Zd\n", pubK.modulus);

	//RSAEP(&pubK, m, c);
	//RSADP(&privK, c, m);
	return 0;
}
