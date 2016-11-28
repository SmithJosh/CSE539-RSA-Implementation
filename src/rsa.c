#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <gmp.h>
#include <openssl/sha.h>
#include "rsa.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <math.h>
#include <assert.h>

// Convert nonnegative integer x to a zero-padded octet string of length xLen.
char* I2OSP(mpz_t x, int xLen) {                                              
    size_t osLen = mpz_sizeinbase(x, 16);                                     
    xLen *= 2;                                                                
    if (xLen < osLen) {                                                       
        printf("integer too large\n");                                        
        return NULL;                                                          
    }                                                                         
    char *os = malloc((xLen + 1) * sizeof(char));                             
    memset(os, '0', xLen - osLen);                                            
    mpz_get_str(os + xLen - osLen, 16, x);                                    
    os[xLen] = '\0';                                                          
    return os;                                                                
}                                                                             

// Convert octet string to a nonnegative integer
void OS2IP(char *X, mpz_t x) {
	mpz_set_str(x, X, 16);
}

// RSA Encryption Primative
int RSAEP(struct RSAPublicKey *K, mpz_t m, mpz_t c) {
	if (mpz_cmp(m, K->modulus) <= 0) {
		printf("message representative out of range\n");
		return 0;
	}
	mpz_powm_sec(c, m, K->publicExponent, K->modulus);
	return 1;
}

// RSA Decryption Primative
int RSADP(struct RSAPrivateKey *K, mpz_t c, mpz_t m) {
	if (mpz_cmp(c, K->modulus) <= 0) {
		printf("ciphertext representative out of range\n");
		return 0;
	}
	mpz_powm_sec(m, c, K->privateExponent, K->modulus);
	return 1;
}

// Mask generation function specified in PKCS #1 Appendix B.                  
char* MGF1(char *mgfSeed, unsigned long long maskLen) {                       
                                                                              
    // Step 1: Verify maskLen <= (hLen * 2^32)                                
    unsigned long long hLen = SHA256_DIGEST_LENGTH;                           
    if (maskLen > (hLen << 32)) {                                             
        printf("mask too long\n");                                            
        return NULL;                                                          
    }                                                                         
    maskLen *= 2;                                                             
    hLen *= 2;                                                                
                                                                              
    // Step 2: Init T to empty octet string. T consists of TLen SHA256 hashes.
    int TLen = (maskLen + hLen - 1) / hLen;                                   
    char *T = malloc((TLen * hLen) * sizeof(char));                           
                                                                              
    char *TPtr = T;                                                           
    char *hashOp;                                                             
    size_t mgfSeedLen = strlen(mgfSeed);                                      
    hashOp = malloc((mgfSeedLen + 4 * 2) * sizeof(char));                     
    memcpy(hashOp, mgfSeed, mgfSeedLen);                                      
                                                                              
    // Step 3: Generate mask                                                  
    int i, j;                                                                 
    char *C;                                                                  
    unsigned char *hash;                                                      
    unsigned char hChar;                                                      
    hash = malloc(SHA256_DIGEST_LENGTH * sizeof(char));                       
    mpz_t counter;                                                            
    mpz_init(counter);                                                        
    for (i = 0; i < TLen; ++i) {                                              
        mpz_set_ui(counter, i);                                               
        C = I2OSP(counter, 4);                                                
        memcpy(hashOp + mgfSeedLen, C, 4 * 2);                                
        SHA256(hashOp, mgfSeedLen + 4 * 2, hash);                             
        for (j = 0; j < hLen; j += 2)                                         
            sprintf(TPtr + j, "%02x", hash[j/2]);                             
        TPtr += hLen;                                                         
        free(C);                                                              
    }                                                                         
                                                                              
    // Step 4: Output mask                                                    
    char *mask = malloc(maskLen + 1);                                         
    memcpy(mask, T, maskLen);                                                 
    mask[maskLen] = '\0';                                                     
    free(hash); free(hashOp); free(T);
    return mask;                                                
}                                                                             

// Temporary function for generating random octet strings.
char* randOS(int length) {
	length *= 2;
	srand(time(NULL));

	int i;
	char *str = malloc(length + 1);
	for (i = 0; i < length; i += 2)
		sprintf(str + i, "%02x", (unsigned char)(rand() % 256));
	str[length] = '\0';
	return str;
}

// M and L are octet strings with no whitespace
char* RSA_OAEP_ENCRYPT(struct RSAPublicKey *K, char* M, char *L) {	

	// Step 1: Length checking (*_o stores size in octets; *_h in hex chars)
	size_t k_o = (mpz_sizeinbase(K->modulus, 16) + 1) / 2;
	size_t hLen_o = SHA256_DIGEST_LENGTH;
	size_t mLen_o = strlen(M) / 2;
	size_t maxmLen_o = k_o - 2 * hLen_o - 2;
	if (mLen_o > maxmLen_o) {
		printf("message too long\n");
		return NULL;
	}
	size_t k_h = k_o * 2;
	size_t hLen_h = hLen_o * 2;
	size_t mLen_h = mLen_o * 2;	// If M is valid, then mLen_h = strlen(M) 

	// Step 2: EME-OAEP encoding
	if (L == NULL) L = "";
	char *lHash = SHA256(L, strlen(L), NULL);	

	// b. Generate random padding string (PS)
	size_t PSLen_h = (maxmLen_o - mLen_o) * 2;
	char *PS = malloc(PSLen_h * sizeof(char));
	memset(PS, '0', PSLen_h);

	// c. Generate data block (DB)
	size_t DBLen_o = k_o - hLen_o - 1;
	size_t DBLen_h = DBLen_o * 2;
	char *DB = malloc(DBLen_h * sizeof(char));
	int i;
	for (i = 0; i < hLen_o; ++i) 
		sprintf(DB + 2 * i, "%02x", lHash[i]);
	memcpy(DB + hLen_h, PS, PSLen_h);
	memcpy(DB + hLen_h + PSLen_h, "01", 2);
	memcpy(DB + DBLen_h - mLen_h, M, mLen_h);
	
	// d. Generate random seed
	char *seed = randOS(hLen_o);

	// ef. Generate dbMask and compute DB XOR dbMask
	char *dbMask = MGF1(seed, DBLen_o);
	char *maskedDB = malloc(DBLen_h * sizeof(char));
	for (i = 0; i < DBLen_h; ++i)
		maskedDB[i] = DB[i] ^ dbMask[i];

	// gh. Generate seedMask and compute seed XOR seedMask
	char *seedMask = MGF1(seed, hLen_o);
	char *maskedSeed = malloc(hLen_h * sizeof(char));
	for (i = 0; i < hLen_h; ++i)
		maskedSeed[i] = seed[i] ^ seedMask[i];
			
 	// i. Generate encoded message (EM)
	size_t EMLen_h = hLen_h + DBLen_h + 2;
	char *EM = malloc((EMLen_h + 1) * sizeof(char));
	memset(EM, 0, 2);
	memcpy(EM + 2, maskedSeed, hLen_h);
	memcpy(EM + hLen_h, maskedDB, DBLen_h);
	EM[EMLen_h] = '\0';

	// Step 3-4: RSA encryption
	mpz_t m, c;
	mpz_init(m);
	mpz_init(c);
	OS2IP(EM, m);
	RSAEP(K, m, c);
	char *C = I2OSP(c, k_o);

	// Free memory
	free(PS); free(DB); free(dbMask); free(maskedDB);
	free(seedMask); free(maskedSeed); free(EM);
	mpz_clear(m); mpz_clear(c);

	return C;
}

char *RSA_OAEP_DECRYPT(struct RSAPrivateKey *K, char* C, char *L) {
	
	// Step 1: Length checking (*_o stores sizes in octets; *_h in hex chars)
	size_t k_o = (mpz_sizeinbase(K->modulus, 16) + 1) / 2;
	size_t CLen_o = sizeof(C) / 2;
	if (k_o != CLen_o) {
		printf("decryption error\n");
		return NULL;	
	}
	size_t hLen_o = SHA256_DIGEST_LENGTH;
	if (k_o < (2 * hLen_o + 2)) {
		printf("decryption error\n");
		return NULL;
	}

	// Step 2: RSA Decryption
	mpz_t c, m;
	mpz_init(c);
	mpz_init(m);
	OS2IP(C, c);
	if (!RSADP(K, c, m)) {
		printf("decryption error\n");
		return NULL;
	}
	char *EM = I2OSP(m, k_o);

	// Step 3: EME-OAEP decoding
	if (L == NULL) L = "";
	size_t hLen_h = hLen_o * 2;
	char *lHash_o = malloc(hLen_o * sizeof(char));
	char *lHash_h = malloc(hLen_h * sizeof(char));
	SHA256(L, strlen(L), lHash_o);
	int i;
	for (i = 0; i < hLen_o; ++i)
		sprintf(lHash_h + 2 * i, "%02x", lHash_o[i]);

	// b. Separate encoded message (EM) into its component parts
	size_t DBLen_o = k_o - hLen_o - 1;
	size_t DBLen_h = DBLen_o * 2;
	char *maskedSeed = malloc((hLen_h + 1) * sizeof(char));
	char *maskedDB = malloc((DBLen_h + 1) * sizeof(char));
	memcpy(maskedSeed, EM + 2, hLen_h);
	memcpy(maskedDB, EM + 2 + hLen_h, DBLen_h);
	maskedSeed[hLen_h] = '\0';
	maskedDB[DBLen_h] = '\0';

	// cd. Generate seedMask and compute maskedSeed XOR seedMask
	char *seedMask = MGF1(maskedDB, hLen_o);
	char *seed = malloc((hLen_h + 1) * sizeof(char));
	for (i = 0; i < hLen_h; ++i)
		seed[i] = maskedSeed[i] ^ seedMask[i];
	seed[hLen_h] = '\0';	

	// ef. Generate dbMask and compute maskedDB XOR dbMask
	char *dbMask = MGF1(seed, DBLen_o);
	char *DB = malloc((DBLen_h + 1) * sizeof(char));
	for (i = 0; i < DBLen_h; ++i)
		DB[i] = maskedDB[i] ^ dbMask[i];
	DB[DBLen_h] = '\0';
	
	// g. Separate data block (DB) into component parts to recover message
	size_t PSLen_h = strlen(DB + hLen_h);
	int mLen_h = DBLen_h - PSLen_h - hLen_h - 1;
	if (mLen_h < 0) {
		printf("decryption error");
		return NULL;
	}
	if (EM[0] != '0' || EM[1] != '0') {
		printf("decryption error");
		return NULL;
	}
	if (strncmp(DB, lHash_h, hLen_h) != 0) {
		printf("decryption error");
		return NULL;
	}
	char *M = malloc((mLen_h + 1) * sizeof(char));
	memcpy(M, DB + DBLen_h - mLen_h, mLen_h);
	M[mLen_h] = '\0';
	return M;
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
	mpz_init_set(pubK.modulus, mod);
	mpz_init_set(privK.modulus, mod);
	mpz_init_set_str(pubK.publicExponent, "01 00 01", 16);	

    gmp_printf("%Zd\n", pubK.modulus);
	gmp_printf("%Zd\n", pubK.publicExponent);

	return 0;
}
