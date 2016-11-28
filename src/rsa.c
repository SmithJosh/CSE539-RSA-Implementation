#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <gmp.h>
#include "rsa.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <math.h>
#include <assert.h>

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

void PRNG(mpz_t rand, int n) {

    int devrandom = open("/dev/random", O_RDONLY);
    char randbits[n/8];
    size_t randlen = 0;
    while (randlen < sizeof randbits) {

        ssize_t result = read(devrandom, randbits + randlen, (sizeof randbits) - randlen);
        if (result < 0)
            printf("%s\n", "Could not read from /dev/random");
        randlen += result;
    }
    close(devrandom);

    mpz_import(rand, sizeof(randbits), 1, sizeof(randbits[0]), 0, 0, randbits);
    // Make sure rand is odd
    if (mpz_odd_p(rand) == 0) {
        unsigned long int one = 1;
        mpz_add_ui(rand, rand, one);
    }
}

void gen_e(mpz_t e) {
    // Set e to 2^16 + 1
    unsigned long int e_int = pow(2,16)+1;
    mpz_set_ui(e, e_int);
}

void gen_probable_prime(mpz_t p, mpz_t p1, mpz_t p2, mpz_t e, int n) {

    // Step 1: Check if p1 and p2 are coprime
    mpz_t gcd, twop1;
    mpz_init(gcd); mpz_init(twop1);
    unsigned long int one = 1;
    unsigned long int two = 2;
    mpz_mul_ui(twop1, p1, two);
    mpz_gcd(gcd, twop1, p2);
    if (mpz_cmp_ui(gcd, one) != 0) {
        fprintf(stderr, "Auxiliaries p1 and p2 not coprime");
        exit(-1);
    }
    
    // Step 2: Chinese remainder theorem
    mpz_t R; mpz_t R1; mpz_t R2;
    mpz_init(R); mpz_init(R1); mpz_init(R2);

    mpz_invert(R1, p2, twop1);
    mpz_mul(R1, R1, p2);

    mpz_invert(R2, twop1, p2);
    mpz_mul(R2, R2, twop1);

    mpz_sub(R, R1, R2);

    // Check for CRT
    mpz_t check1; mpz_t check2; mpz_t mpz_one; 
    mpz_init(check1); mpz_init(check2); mpz_init(mpz_one); 
    mpz_set_str(mpz_one, "1", 10);
    mpz_mod(check1, R, twop1);
    mpz_mod(check2, R, p2);
    mpz_sub(check2, p2, check2);
    assert(mpz_cmp(check1, mpz_one) == 0);
    assert(mpz_cmp(check2, mpz_one) == 0);


    // Step 3: Generate random X between lower_bound and upper_bound
    mpz_t lower_bound; mpz_t upper_bound; mpz_t base; mpz_t X; mpz_t temp; mpz_t Y; 
    mpz_init(lower_bound); mpz_init(upper_bound); mpz_init(base); mpz_init(X); mpz_init(temp); mpz_init(Y);

    mpz_set_str(base, "2", 10);
    mpz_pow_ui(upper_bound, base, n/2);
    mpz_sub_ui(upper_bound, upper_bound, one);


    mpf_t f_lb, f_sqrt, f_base;

    mpf_init(f_lb); mpf_init(f_sqrt); mpf_init_set_str(f_base, "2", 10);

    mpf_sqrt(f_sqrt, f_base);
    mpf_pow_ui(f_lb, f_base, n/2-1);
    mpf_mul(f_lb, f_lb, f_sqrt);
    mpz_set_f(lower_bound, f_lb);

    
    // Step 6: Check condition for Y > cond
    mpz_t cond;
    mpz_init(cond);
    mpz_pow_ui(cond, base, n/2);

    mpz_t Y_minus_1; 
    mpz_init(Y_minus_1);
    mpz_sub_ui(Y_minus_1, Y, one);


    int i = 0;
    do {

        PRNG(X, n/2);
        while (mpz_cmp(X, lower_bound) < 0 || mpz_cmp(X, upper_bound) > 0) {
            PRNG(X, n/2);
        }

        // Step 4: Calculate Y
        mpz_mul(temp, twop1, p2);
        mpz_sub(Y, R, X);
        mpz_mod(Y, Y, temp);
        mpz_add(Y, Y, X);

        i = 0;

        mpz_gcd(gcd, Y_minus_1, e);

        while (mpz_cmp(Y, cond) < 0) {
            i += 1;
            if (mpz_cmp_ui(gcd, one) != 0) {
                if (i >= 5*(n/2)) {
                    printf("%s\n", "FAILURE");
                    exit(-1);
                }
                mpz_add(Y, Y, temp);
                mpz_gcd(gcd, Y_minus_1, e);
            }
            else {
                if (mpz_probab_prime_p(Y, 28) >= 1) {
                    mpz_set(p, Y);
                    return;
                }
                if (i >= 5*(n/2)) {
                    printf("%s\n", "FAILURE");
                    exit(-1);
                }
                mpz_add(Y, Y, temp);
                mpz_gcd(gcd, Y_minus_1, e);
            }
        }
    } while (mpz_cmp(Y, cond) >= 0);

    mpz_clear(gcd); mpz_clear(twop1); mpz_clear(R); mpz_clear(R1); mpz_clear(R2); 
    mpz_clear(check1); mpz_clear(check2); mpz_clear(mpz_one);
    mpz_clear(lower_bound); mpz_clear(upper_bound); mpz_clear(base); mpz_clear(X); mpz_clear(temp); mpz_clear(Y);
    mpz_clear(cond); mpz_clear(Y_minus_1);

    mpf_clear(f_lb); mpf_clear(f_sqrt); mpf_clear(f_base);
}


void gen_primes(mpz_t p, mpz_t e, int n) {
    if (n != 1024 && n != 2048 && n != 3072) {
        fprintf(stderr, "Invalid bit length for RSA modulus. Exiting...\n");
        exit(-1);
    }
    mpz_t xp, xp1, xp2, p1, p2;
    mpz_init(xp); mpz_init(xp1); mpz_init(xp2); mpz_init(p1); mpz_init(p2); 
    unsigned long int two = 2;
    
    PRNG(xp1, 104);
    PRNG(xp2, 104);

    while (mpz_probab_prime_p(xp1, 28) != 1) {
        mpz_add_ui(xp1, xp1, two); 
    }
    while (mpz_probab_prime_p(xp2, 28) != 1) {
        mpz_add_ui(xp2, xp2, two);
    }
    gmp_printf("%s\n%Zd\n%Zd\n", "Auxiliary primes for p: ", xp1, xp2);
    mpz_set(p1, xp1);
    mpz_set(p2, xp2);

    gen_probable_prime(p, p1, p2, e, n);
    mpz_clear(xp); mpz_clear(xp1); mpz_clear(xp2); mpz_clear(p1); mpz_clear(p2); 
}

// Determine whether n is prime. Return 2 is definitely prime, 1 if probably prime, 0 if non-prime.
// Uses Miller-Rabin primality tests. Use reps between 15-50.
int mpz_probab_prime_p(const mpz_t n, int reps);

// Generate RSA modulus using two odd primes for now. Miller Rabin only set to 15. Specify number of bits
// Also, this is deterministic at the moment. Will change later...
/*
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
*/

// Generate random number w/ bitlength n
void mpz_rrandomb(mpz_t rop, gmp_randstate_t state, mp_bitcnt_t n);

// Sets rop to GCD of op1 and op2
void mpz_gcd(mpz_t rop, const mpz_t op1, const mpz_t op2);

int main() {		
	struct RSAPublicKey pubK;
	struct RSAPrivateKey privK;
	mpz_t mod, e, d, m, c, p, q;
    mpz_init(mod); mpz_init(e); mpz_init(d); mpz_init(p); mpz_init(q);
	mpz_init(m); mpz_init(c);
    
    gen_e(e);
    gmp_printf("%s%Zd\n", "The public exponent e is: ", e);
    PRNG(p, 16);
    gen_primes(p, e, 1024);
    gen_primes(q, e, 1024);
    gmp_printf("%s%Zd\n", "Generated prime p: ", p);
    gmp_printf("%s%Zd\n", "Generated prime q: ", q);
    //gen_modulus(mod, r1, r2, 40);
    //gen_e(e, mod, r1, r2);

	OS2IP("8c 69 50", mod);
	mpz_set(pubK.modulus, mod);
	mpz_set(privK.modulus, mod);
	mpz_set_str(pubK.publicExponent, "01 00 01", 16);

    gmp_printf("%Zd\n", pubK.modulus);

	//RSAEP(&pubK, m, c);
	//RSADP(&privK, c, m);
	return 0;
}
