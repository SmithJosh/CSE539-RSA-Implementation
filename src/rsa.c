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
	if (mpz_cmp(m, K->modulus) >= 0) {
		printf("message representative out of range\n");
		return 0;
	}
	mpz_powm_sec(c, m, K->publicExponent, K->modulus);
	return 1;
}

// RSA Decryption Primative
int RSADP(struct RSAPrivateKey *K, mpz_t c, mpz_t m) {
	if (mpz_cmp(c, K->modulus) >= 0) {
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

// RSA Encryption with OAEP. Section 7.1.1 in PKCS #1
char* RSAES_OAEP_ENCRYPT(struct RSAPublicKey *K, char* M, char *L) {	

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
	char *DB = malloc((DBLen_h + 1) * sizeof(char));
	int i;
	for (i = 0; i < hLen_o; ++i) 
		sprintf(DB + 2 * i, "%02x", (unsigned char)lHash[i]);
	memcpy(DB + hLen_h, PS, PSLen_h);
	memcpy(DB + hLen_h + PSLen_h, "01", 2);
	memcpy(DB + DBLen_h - mLen_h, M, mLen_h);
	DB[DBLen_h] = '\0';

	// d. Generate random seed
	mpz_t seed;
	mpz_init(seed);
	PRNG(seed, hLen_o * 8);
	char *seedStr = I2OSP(seed, hLen_o);

	// ef. Generate dbMask and compute DB XOR dbMask
	char *dbMask = MGF1(seedStr, DBLen_o);
	mpz_t op1, op2, rop;
	mpz_init_set_str(op1, DB, 16);
	mpz_init_set_str(op2, dbMask, 16);
	mpz_init(rop);
	mpz_xor(rop, op1, op2);
	char *maskedDB = I2OSP(rop, DBLen_o);	

	// gh. Generate seedMask and compute seed XOR seedMask
	char *seedMask = MGF1(maskedDB, hLen_o);
	mpz_set_str(op1, seedStr, 16);
	mpz_set_str(op2, seedMask, 16);
	mpz_xor(rop, op1, op2);
	char *maskedSeed = I2OSP(rop, hLen_o);

 	// i. Generate encoded message (EM)
	size_t EMLen_h = hLen_h + DBLen_h + 2;
	char *EM = malloc((EMLen_h + 1) * sizeof(char));
	memset(EM, '0', 2);
	memcpy(EM + 2, maskedSeed, hLen_h);
	memcpy(EM + hLen_h + 2, maskedDB, DBLen_h);
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
	mpz_clear(op1); mpz_clear(op2); mpz_clear(rop);
	mpz_clear(m); mpz_clear(c);

	return C;
}

// RSA Decryption with OAEP. Section 7.1.2 in PKCS #1
char *RSAES_OAEP_DECRYPT(struct RSAPrivateKey *K, char* C, char *L) {
	
	// Step 1: Length checking (*_o stores sizes in octets; *_h in hex chars)
	size_t k_o = (mpz_sizeinbase(K->modulus, 16) + 1) / 2;
	size_t CLen_o = strlen(C) / 2;
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
		sprintf(lHash_h + 2 * i, "%02x", (unsigned char)lHash_o[i]);

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
	mpz_t op1, op2, rop;
	mpz_init_set_str(op1, maskedSeed, 16);
	mpz_init_set_str(op2, seedMask, 16);
	mpz_init(rop);
	mpz_xor(rop, op1, op2);
	char *seed = I2OSP(rop, hLen_o);

	// ef. Generate dbMask and compute maskedDB XOR dbMask
	char *dbMask = MGF1(seed, DBLen_o);
	mpz_set_str(op1, maskedDB, 16);
	mpz_set_str(op2, dbMask, 16);
	mpz_xor(rop, op1, op2);
	char *DB = I2OSP(rop, DBLen_o);
	
	// g. Separate data block (DB) into component parts to recover message
	size_t PSLen_h = strstr(DB + hLen_h, "01") - DB - hLen_h;
	int mLen_h = DBLen_h - PSLen_h - hLen_h - 1;
	int errCount = 0;
	errCount += (mLen_h < 0);
	errCount += !(EM[0] == '0' && EM[1] == '0');
	errCount += (strncmp(DB, lHash_h, hLen_h) != 0);
	if (errCount  > 0) {
		printf("decryption error\n");
		return NULL;
	}
	char *M = malloc((mLen_h + 1) * sizeof(char));
	memcpy(M, DB + DBLen_h - mLen_h + 1, mLen_h);
	M[mLen_h] = '\0';

	// Free memory
	free(EM); free(lHash_o); free(lHash_h); free(maskedSeed); free(maskedDB);
	free(seedMask); free(seed); free(dbMask); free(DB);
	mpz_clear(op1); mpz_clear(op2); mpz_clear(rop);
	mpz_clear(m); mpz_clear(c);
	
	return M;
}

// Generates pseudorandom n bits from /dev/random file
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

// Generate (constant) public exponent e
void gen_e(mpz_t e) {
    // Set e to 2^16 + 1
    unsigned long int e_int = pow(2,16)+1;
    mpz_set_ui(e, e_int);
}

// Generate private exponent d
void gen_d(mpz_t d, mpz_t p_minus_1, mpz_t q_minus_1, mpz_t e, int n) {

    unsigned long int one = 1;
    mpz_t lower_bound, upper_bound, base;
    mpz_init(lower_bound); mpz_init(upper_bound); mpz_init_set_str(base, "2", 10);
    mpz_pow_ui(lower_bound, base, n/2);
    mpz_lcm(upper_bound, p_minus_1, q_minus_1);

    mpz_invert(d, e, upper_bound);
    if (mpz_cmp(d, lower_bound) < 0 || mpz_cmp(d, upper_bound) > 0) {
        fprintf(stderr, "Private exponent d too small, try again\n");
        exit(-1);
    }

    mpz_t ed, check_d;
    mpz_init(ed); mpz_init(check_d);
    
    mpz_mul(ed, e, d);
    mpz_mod(check_d, ed, upper_bound);

    assert(mpz_cmp_ui(check_d, one) == 0);
 
}

// Generate probable prime from auxiliary primes
void gen_probable_prime(mpz_t p, mpz_t p1, mpz_t p2, mpz_t e, int n) {

    // Step 1: Check if p1 and p2 are coprime
    mpz_t gcd, twop1;
    mpz_init(gcd); mpz_init(twop1);
    unsigned long int one = 1;
    unsigned long int two = 2;
    mpz_mul_ui(twop1, p1, two);
    mpz_gcd(gcd, twop1, p2);
    if (mpz_cmp_ui(gcd, one) != 0) {
        fprintf(stderr, "Auxiliaries p1 and p2 not coprime\n");
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

    
    mpz_t cond;
    mpz_init(cond);
    mpz_pow_ui(cond, base, n/2);

    mpz_t Y_minus_1; 
    mpz_init(Y_minus_1);
    

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
        mpz_sub_ui(Y_minus_1, Y, one);


        // Step 5: i = 0
        i = 0;

        mpz_gcd(gcd, Y_minus_1, e);

        // Step 11: Go to Step 6
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
            // Step 7: If GCD(Y-1, e) = 1
            else {
                if (mpz_probab_prime_p(Y, 28) >= 1) {
                    mpz_set(p, Y);
                    return;
                }

                //Step 8: Check if failure
                if (i >= 5*(n/2)) {
                    printf("%s\n", "FAILURE");
                    exit(-1);
                }

                //Step 10: Update Y
                mpz_add(Y, Y, temp);
                mpz_gcd(gcd, Y_minus_1, e);
            }
        }
    // Step 6: Check condition for Y > cond
    } while (mpz_cmp(Y, cond) >= 0);

    mpz_clear(gcd); mpz_clear(twop1); mpz_clear(R); mpz_clear(R1); mpz_clear(R2); 
    mpz_clear(check1); mpz_clear(check2); mpz_clear(mpz_one);
    mpz_clear(lower_bound); mpz_clear(upper_bound); mpz_clear(base); mpz_clear(X); mpz_clear(temp); mpz_clear(Y);
    mpz_clear(cond); mpz_clear(Y_minus_1);

    mpf_clear(f_lb); mpf_clear(f_sqrt); mpf_clear(f_base);
}


// Generate auxiliary primes
void gen_auxiliary_primes(mpz_t p, mpz_t e, int n) {
    if (n != 1024 && n != 2048 && n != 3072) {
        fprintf(stderr, "Invalid bit length for RSA modulus. Exiting...\n");
        exit(-1);
    }
    mpz_t xp, xp1, xp2, p1, p2;
    mpz_init(xp); mpz_init(xp1); mpz_init(xp2); mpz_init(p1); mpz_init(p2); 
    unsigned long int two = 2;

    int len_aux = 0;
    int mr_rounds = 0;
    if (n == 1024) {
        len_aux = 104;
        mr_rounds = 28;
    }
    else if (n == 2048) {
        len_aux = 144;
        mr_rounds = 38;
    }
    else if (n == 3072) {
        len_aux = 176;
        mr_rounds = 41;
    }
    
    PRNG(xp1, len_aux);
    PRNG(xp2, len_aux);

    while (mpz_probab_prime_p(xp1, mr_rounds) != 1) {
        mpz_add_ui(xp1, xp1, two); 
    }
    while (mpz_probab_prime_p(xp2, mr_rounds) != 1) {
        mpz_add_ui(xp2, xp2, two);
    }
    //gmp_printf("%s\n%Zd\n%Zd\n", "Auxiliary primes for p: ", xp1, xp2);
    mpz_set(p1, xp1);
    mpz_set(p2, xp2);

    gen_probable_prime(p, p1, p2, e, n);
    mpz_clear(xp); mpz_clear(xp1); mpz_clear(xp2); mpz_clear(p1); mpz_clear(p2); 
}

// Check if gcd(a,b) = 1 (coprime)
int coprime(mpz_t a, mpz_t b) {
    int coprime = 1;
    mpz_t gcd; mpz_init(gcd);
    mpz_t one; mpz_init_set_str(one, "1", 10);

    mpz_gcd(gcd, a, b);
    if (mpz_cmp(gcd, one) != 0) {
        coprime = 0;
    }
    mpz_clear(gcd); mpz_clear(one);
    return coprime;
}

/*
int main() {		
	struct RSAPublicKey pubK;
	struct RSAPrivateKey privK;
    mpz_init(pubK.modulus); mpz_init(pubK.publicExponent);
    mpz_init(privK.modulus); mpz_init(privK.privateExponent);
	mpz_t mod, e, d, p, q;
    mpz_init(mod); mpz_init(e); mpz_init(d); mpz_init(p); mpz_init(q);

    // Generate public exponent e
    gen_e(e);
    gmp_printf("%s%Zd\n\n", "Public exponent e: ", e);

    // Generate primes p and q for modulus n
    gen_auxiliary_primes(p, e, 1024);
    gen_auxiliary_primes(q, e, 1024);

    // Check if (p-1) and (q-1) are coprime with e
    unsigned long int one = 1;
    mpz_t p_minus_1, q_minus_1;
    mpz_init(p_minus_1); mpz_init(q_minus_1);
    mpz_sub_ui(p_minus_1, p, one);
    mpz_sub_ui(q_minus_1, q, one);

    assert(coprime(p_minus_1, e) == 1);
    assert(coprime(q_minus_1, e) == 1);

    gmp_printf("%s%Zd\n\n", "Prime p: ", p);
    gmp_printf("%s%Zd\n\n", "Prime q: ", q);

    mpz_mul(mod, p, q);

    gmp_printf("%s%Zd\n\n", "Modulus n: ", mod);

    // Generate private exponent d
    gen_d(d, p_minus_1, q_minus_1, e, 1024);
    
    gmp_printf("%s%Zd\n\n", "Private exponent d: ", d);

    mpz_set(pubK.modulus, mod);
    mpz_set(pubK.publicExponent, e);

    mpz_set(privK.modulus, mod);
    mpz_set(privK.privateExponent, d);

    gmp_printf("%Zd\n", pubK.modulus);
	gmp_printf("%Zd\n", pubK.publicExponent);
    return 1; 
}*/
